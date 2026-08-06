-- Survey Builder Platform: production-minded initial schema
--
-- Design principles:
--   * Published survey versions and their map versions are immutable.
--   * Public response rows never contain an authenticated user id.
--   * Pseudonym-to-user and identified-response-to-user mappings live in a
--     non-exposed schema and are reachable only through narrowly scoped RPCs.
--   * Invitation and join-code secrets are returned once and stored only as
--     one-way hashes (SHA-256 for random tokens, bcrypt for human codes).
--   * All organization access is checked in the database with RLS.

begin;

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Enumerated domain types
-- ---------------------------------------------------------------------------

create type public.organization_role as enum (
  'owner',
  'admin',
  'survey_manager',
  'response_viewer',
  'member'
);

create type public.membership_status as enum ('pending', 'approved', 'rejected');
create type public.membership_join_method as enum ('created_organization', 'invitation', 'join_code', 'manual');
create type public.map_visibility as enum ('public', 'restricted');
create type public.map_source_kind as enum ('static', 'mapbox');
create type public.region_mode as enum ('none', 'rectangular_grid', 'hex_grid', 'uploaded', 'manual');
create type public.integration_provider as enum ('github', 'supabase', 'mapbox');
create type public.integration_status as enum ('not_configured', 'connected', 'disconnected', 'error');
create type public.survey_status as enum ('draft', 'published', 'paused', 'closed', 'archived');
create type public.survey_version_status as enum ('draft', 'published');
create type public.survey_access as enum ('open', 'members');
create type public.privacy_mode as enum ('anonymous', 'pseudonymous', 'identified');
create type public.duplicate_policy as enum ('allow', 'one_per_account', 'one_per_device', 'replace_previous');
create type public.question_type as enum (
  'short_text',
  'long_text',
  'number',
  'date',
  'time',
  'yes_no',
  'single_choice',
  'multiple_choice',
  'dropdown',
  'rating',
  'ranking',
  'matrix',
  'file_upload',
  'image_choice',
  'information',
  'consent',
  'map_tiles',
  'map_markup',
  'map_polygon'
);
create type public.logic_action as enum ('show', 'hide', 'require');
create type public.logic_operator as enum (
  'equals',
  'not_equals',
  'contains',
  'answered',
  'not_answered',
  'greater_than',
  'less_than',
  'selected_region',
  'selected_region_count_at_least',
  'selected_region_count_at_most',
  'drawing_overlaps_region',
  'drawing_touches_region',
  'drawing_inside_region',
  'drawing_contains_region',
  'drawing_avoids_region'
);
create type public.assignment_status as enum ('assigned', 'started', 'completed', 'overdue', 'cancelled');
create type public.response_status as enum ('submitted', 'superseded', 'withdrawn', 'invalidated');
create type public.setting_scope as enum ('organization', 'survey', 'map', 'integration');

-- ---------------------------------------------------------------------------
-- Accounts, organizations, memberships, onboarding, and integrations
-- ---------------------------------------------------------------------------

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint profiles_display_name_length check (char_length(display_name) <= 160)
);

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  description text not null default '',
  primary_admin_id uuid not null references auth.users(id) on delete restrict,
  public_profile_enabled boolean not null default false,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint organizations_name_length check (char_length(name) between 1 and 160),
  constraint organizations_slug_format check (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  constraint organizations_description_length check (char_length(description) <= 4000)
);

create table public.organization_memberships (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.organization_role not null default 'member',
  status public.membership_status not null default 'pending',
  joined_via public.membership_join_method not null default 'manual',
  approved_by uuid references auth.users(id) on delete set null,
  approved_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, user_id),
  constraint memberships_approval_state check (
    (status = 'approved' and approved_at is not null)
    or (status <> 'approved')
  )
);

create table public.organization_notification_recipients (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  email text not null,
  receives_membership_requests boolean not null default true,
  receives_survey_activity boolean not null default false,
  created_at timestamptz not null default now(),
  unique (organization_id, email),
  constraint notification_recipient_email_normalized check (email = lower(btrim(email)))
);

create table public.organization_invitations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  email text not null,
  requested_role public.organization_role not null default 'member',
  token_hash text not null unique,
  expires_at timestamptz not null default (now() + interval '3 days'),
  created_by uuid not null references auth.users(id) on delete restrict,
  accepted_by uuid references auth.users(id) on delete set null,
  accepted_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  constraint invitation_email_normalized check (email = lower(btrim(email))),
  constraint invitation_expiration_after_creation check (expires_at > created_at),
  constraint invitation_terminal_state check (not (accepted_at is not null and revoked_at is not null))
);

create table public.organization_join_codes (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  label text not null default 'Organization join code',
  code_hash text not null,
  is_active boolean not null default true,
  approval_required boolean not null default true,
  expires_at timestamptz,
  max_uses integer,
  use_count integer not null default 0,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  rotated_at timestamptz,
  unique (organization_id, code_hash),
  constraint join_code_use_counts check (
    use_count >= 0 and (max_uses is null or (max_uses > 0 and use_count <= max_uses))
  )
);

create table public.membership_requests (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  membership_id uuid not null unique references public.organization_memberships(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  invitation_id uuid references public.organization_invitations(id) on delete set null,
  join_code_id uuid references public.organization_join_codes(id) on delete set null,
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  constraint membership_request_one_source check (num_nonnulls(invitation_id, join_code_id) <= 1)
);

create table public.organization_integrations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  provider public.integration_provider not null,
  status public.integration_status not null default 'not_configured',
  public_config jsonb not null default '{}'::jsonb,
  secret_reference text,
  connected_by uuid references auth.users(id) on delete set null,
  connected_at timestamptz,
  updated_at timestamptz not null default now(),
  unique (organization_id, provider),
  constraint integration_public_config_object check (jsonb_typeof(public_config) = 'object'),
  constraint integration_secret_not_embedded check (
    not (public_config ?| array['service_role_key', 'client_secret', 'access_token', 'upload_token', 'census_api_key'])
  )
);

-- GitHub OAuth tokens remain in a server-side secret store. This table keeps
-- only the non-secret repository and Pages metadata the organization dashboard
-- needs to explain and monitor deployment.
create table public.organization_github_repositories (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null unique references public.organizations(id) on delete cascade,
  github_installation_id bigint,
  repository_node_id text,
  owner_login text not null,
  repository_name text not null,
  default_branch text not null default 'main',
  pages_enabled boolean not null default false,
  pages_url text,
  deployment_workflow_path text not null default '.github/workflows/deploy-pages.yml',
  last_deployed_sha text,
  last_deployed_at timestamptz,
  connected_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (owner_login, repository_name),
  constraint github_owner_login_present check (char_length(btrim(owner_login)) between 1 and 100),
  constraint github_repository_name_present check (char_length(btrim(repository_name)) between 1 and 100),
  constraint github_pages_url_state check (not pages_enabled or pages_url is not null),
  constraint github_deployed_sha_format check (
    last_deployed_sha is null or last_deployed_sha ~ '^[0-9a-fA-F]{7,64}$'
  )
);

create table public.setting_definitions (
  key text primary key,
  scope public.setting_scope not null,
  label text not null,
  help_text text not null,
  who_is_affected text not null,
  consequences text not null,
  editable_after_publish boolean not null default true,
  requires_confirmation boolean not null default false,
  default_value jsonb not null default 'null'::jsonb,
  validation_schema jsonb not null default '{}'::jsonb,
  constraint setting_definition_key_format check (key ~ '^[a-z][a-z0-9_.-]+$'),
  constraint setting_validation_schema_object check (jsonb_typeof(validation_schema) = 'object')
);

create table public.organization_setting_values (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  setting_key text not null references public.setting_definitions(key) on delete restrict,
  value jsonb not null,
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now(),
  primary key (organization_id, setting_key)
);

-- ---------------------------------------------------------------------------
-- Maps and immutable map versions
-- ---------------------------------------------------------------------------

create table public.map_assets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  description text not null default '',
  alt_text text not null,
  visibility public.map_visibility not null default 'restricted',
  archived_at timestamptz,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint map_asset_name_length check (char_length(name) between 1 and 200),
  constraint map_asset_alt_text_present check (char_length(btrim(alt_text)) between 1 and 1000)
);

create table public.map_versions (
  id uuid primary key default gen_random_uuid(),
  map_asset_id uuid not null references public.map_assets(id) on delete cascade,
  version_number integer not null,
  source_kind public.map_source_kind not null,
  region_mode public.region_mode not null default 'none',
  static_bucket text,
  static_object_path text,
  original_filename text,
  mime_type text,
  width_pixels integer,
  height_pixels integer,
  checksum_sha256 text,
  bounds_west double precision,
  bounds_south double precision,
  bounds_east double precision,
  bounds_north double precision,
  mapbox_style_url text,
  mapbox_tileset_url text,
  mapbox_source_layer text,
  geocoding_enabled boolean not null default false,
  processing_metadata jsonb not null default '{}'::jsonb,
  locked_at timestamptz,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  unique (map_asset_id, version_number),
  constraint map_version_positive check (version_number > 0),
  constraint map_dimensions_positive check (
    (width_pixels is null or width_pixels > 0) and (height_pixels is null or height_pixels > 0)
  ),
  constraint map_bounds_complete check (
    num_nonnulls(bounds_west, bounds_south, bounds_east, bounds_north) in (0, 4)
  ),
  constraint map_bounds_valid check (
    bounds_west is null
    or (
      bounds_west between -180 and 180
      and bounds_east between -180 and 180
      and bounds_south between -90 and 90
      and bounds_north between -90 and 90
      and bounds_west < bounds_east
      and bounds_south < bounds_north
    )
  ),
  constraint map_source_fields check (
    (
      source_kind = 'static'
      and static_bucket is not null
      and static_object_path is not null
      and mapbox_style_url is null
      and mapbox_tileset_url is null
      and mapbox_source_layer is null
      and geocoding_enabled = false
    )
    or (
      source_kind = 'mapbox'
      and mapbox_style_url is not null
      and static_bucket is null
      and static_object_path is null
    )
  ),
  constraint map_processing_metadata_object check (jsonb_typeof(processing_metadata) = 'object')
);

create table public.map_regions (
  id uuid primary key default gen_random_uuid(),
  map_version_id uuid not null references public.map_versions(id) on delete cascade,
  region_key text not null,
  label text not null,
  geometry jsonb not null,
  properties jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (map_version_id, region_key),
  constraint map_region_key_format check (region_key ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  constraint map_region_geometry_shape check (jsonb_typeof(geometry) in ('array', 'object')),
  constraint map_region_properties_object check (jsonb_typeof(properties) = 'object')
);

-- ---------------------------------------------------------------------------
-- Survey identities, immutable versions, questions, and conditional logic
-- ---------------------------------------------------------------------------

create table public.surveys (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  slug text not null,
  status public.survey_status not null default 'draft',
  current_draft_version_id uuid,
  current_published_version_id uuid,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  archived_at timestamptz,
  deleted_at timestamptz,
  deletion_due_at timestamptz,
  status_before_deletion public.survey_status,
  unique (organization_id, slug),
  constraint survey_slug_format check (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  constraint survey_deletion_state check (
    (
      deleted_at is null
      and deletion_due_at is null
      and status_before_deletion is null
    )
    or (
      deleted_at is not null
      and deletion_due_at is not null
      and deletion_due_at >= deleted_at
      and status_before_deletion is not null
      and status = 'archived'
      and archived_at is not null
    )
  )
);

create table public.survey_versions (
  id uuid primary key default gen_random_uuid(),
  survey_id uuid not null references public.surveys(id) on delete cascade,
  version_number integer not null,
  status public.survey_version_status not null default 'draft',
  parent_version_id uuid references public.survey_versions(id) on delete set null,
  title text not null,
  purpose text not null default '',
  access public.survey_access not null default 'open',
  privacy public.privacy_mode not null default 'anonymous',
  pseudonymous_linking_enabled boolean not null default false,
  duplicate_policy public.duplicate_policy not null default 'allow',
  allow_save_and_resume boolean not null default true,
  opens_at timestamptz,
  closes_at timestamptz,
  response_limit integer,
  retention_days integer,
  completion_message text not null default 'Thank you for your response.',
  appearance jsonb not null default '{}'::jsonb,
  notification_config jsonb not null default '{}'::jsonb,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  published_at timestamptz,
  unique (survey_id, version_number),
  constraint survey_version_positive check (version_number > 0),
  constraint survey_version_title_length check (char_length(title) between 1 and 240),
  constraint survey_version_schedule check (closes_at is null or opens_at is null or closes_at > opens_at),
  constraint survey_version_response_limit check (response_limit is null or response_limit > 0),
  constraint survey_version_retention check (retention_days is null or retention_days >= 1),
  constraint survey_version_pseudonym_linking check (
    not pseudonymous_linking_enabled or privacy = 'pseudonymous'
  ),
  constraint survey_version_anonymous_duplicate_check check (
    privacy <> 'anonymous' or duplicate_policy <> 'one_per_account'
  ),
  constraint survey_version_publish_state check (
    (status = 'draft' and published_at is null)
    or (status = 'published' and published_at is not null)
  ),
  constraint survey_appearance_object check (jsonb_typeof(appearance) = 'object'),
  constraint survey_notification_config_object check (jsonb_typeof(notification_config) = 'object')
);

alter table public.surveys
  add constraint surveys_current_draft_fk
  foreign key (current_draft_version_id) references public.survey_versions(id)
  on delete set null deferrable initially deferred;

alter table public.surveys
  add constraint surveys_current_published_fk
  foreign key (current_published_version_id) references public.survey_versions(id)
  on delete set null deferrable initially deferred;

create unique index one_draft_version_per_survey
  on public.survey_versions(survey_id)
  where status = 'draft';

create table public.survey_version_setting_values (
  survey_version_id uuid not null references public.survey_versions(id) on delete cascade,
  setting_key text not null references public.setting_definitions(key) on delete restrict,
  value jsonb not null,
  primary key (survey_version_id, setting_key)
);

create table public.survey_questions (
  id uuid primary key default gen_random_uuid(),
  survey_version_id uuid not null references public.survey_versions(id) on delete cascade,
  question_key uuid not null default gen_random_uuid(),
  position integer not null,
  type public.question_type not null,
  title text not null,
  description text not null default '',
  required boolean not null default false,
  map_version_id uuid references public.map_versions(id) on delete restrict,
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (survey_version_id, question_key),
  unique (survey_version_id, position),
  constraint survey_question_position check (position >= 0),
  constraint survey_question_title_length check (char_length(title) between 1 and 1000),
  constraint survey_question_map_reference check (
    (type in ('map_tiles', 'map_markup', 'map_polygon') and map_version_id is not null)
    or (type not in ('map_tiles', 'map_markup', 'map_polygon') and map_version_id is null)
  ),
  constraint survey_question_settings_object check (jsonb_typeof(settings) = 'object')
);

create table public.survey_question_options (
  id uuid primary key default gen_random_uuid(),
  question_id uuid not null references public.survey_questions(id) on delete cascade,
  option_key uuid not null default gen_random_uuid(),
  position integer not null,
  label text not null,
  value text not null,
  image_url text,
  image_storage_path text,
  unique (question_id, option_key),
  unique (question_id, position),
  unique (question_id, value),
  constraint survey_option_position check (position >= 0),
  constraint survey_option_label_present check (char_length(btrim(label)) between 1 and 500),
  constraint survey_option_image_url_safe check (
    image_url is null
    or (
      char_length(image_url) <= 262144
      and (
        image_url ~ '^https://[^[:space:]]+$'
        or image_url ~ '^data:image/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$'
      )
    )
  )
);

create table public.survey_map_trigger_areas (
  id uuid primary key default gen_random_uuid(),
  survey_version_id uuid not null references public.survey_versions(id) on delete cascade,
  map_version_id uuid not null references public.map_versions(id) on delete restrict,
  area_key text not null,
  label text not null,
  geometry jsonb not null,
  created_at timestamptz not null default now(),
  unique (survey_version_id, area_key),
  constraint trigger_area_key_format check (area_key ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'),
  constraint trigger_area_geometry_shape check (jsonb_typeof(geometry) in ('array', 'object'))
);

create table public.survey_logic_rules (
  id uuid primary key default gen_random_uuid(),
  survey_version_id uuid not null references public.survey_versions(id) on delete cascade,
  position integer not null,
  source_question_id uuid not null references public.survey_questions(id) on delete cascade,
  target_question_id uuid not null references public.survey_questions(id) on delete cascade,
  operator public.logic_operator not null,
  action public.logic_action not null,
  comparison_value jsonb,
  trigger_area_id uuid references public.survey_map_trigger_areas(id) on delete restrict,
  overlap_threshold numeric(5,4),
  created_at timestamptz not null default now(),
  unique (survey_version_id, position),
  constraint survey_logic_position check (position >= 0),
  constraint survey_logic_not_self check (source_question_id <> target_question_id),
  constraint survey_logic_overlap_threshold check (
    overlap_threshold is null or overlap_threshold between 0 and 1
  ),
  constraint survey_logic_spatial_fields check (
    (
      operator in (
        'drawing_overlaps_region', 'drawing_touches_region', 'drawing_inside_region',
        'drawing_contains_region', 'drawing_avoids_region'
      )
      and trigger_area_id is not null
    )
    or (
      operator not in (
        'drawing_overlaps_region', 'drawing_touches_region', 'drawing_inside_region',
        'drawing_contains_region', 'drawing_avoids_region'
      )
      and trigger_area_id is null
      and overlap_threshold is null
    )
  )
);

-- ---------------------------------------------------------------------------
-- Responses, cross-device drafts, assignments, and separated identity data
-- ---------------------------------------------------------------------------

create table public.survey_responses (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  survey_id uuid not null references public.surveys(id) on delete cascade,
  survey_version_id uuid not null references public.survey_versions(id) on delete restrict,
  privacy public.privacy_mode not null,
  pseudonym_id uuid,
  answers jsonb not null,
  status public.response_status not null default 'submitted',
  started_at timestamptz,
  submitted_at timestamptz not null default now(),
  superseded_by uuid references public.survey_responses(id) on delete set null,
  invalidation_reason text,
  metadata jsonb not null default '{}'::jsonb,
  constraint response_answers_object check (jsonb_typeof(answers) = 'object'),
  constraint response_metadata_object check (jsonb_typeof(metadata) = 'object'),
  constraint response_pseudonym_mode check (
    (privacy = 'pseudonymous' and pseudonym_id is not null)
    or (privacy <> 'pseudonymous' and pseudonym_id is null)
  ),
  constraint response_supersession check (
    (status = 'superseded' and superseded_by is not null)
    or (status <> 'superseded')
  )
);

create table public.response_drafts (
  id uuid primary key default gen_random_uuid(),
  survey_version_id uuid not null references public.survey_versions(id) on delete cascade,
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  answers jsonb not null default '{}'::jsonb,
  current_question_key uuid,
  started_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  expires_at timestamptz,
  unique (survey_version_id, owner_user_id),
  constraint response_draft_answers_object check (jsonb_typeof(answers) = 'object')
);

create table public.survey_assignments (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  survey_id uuid not null references public.surveys(id) on delete cascade,
  survey_version_id uuid not null references public.survey_versions(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete cascade,
  assigned_by uuid not null references auth.users(id) on delete restrict,
  due_at timestamptz,
  reminder_enabled boolean not null default false,
  reminder_config jsonb not null default '{}'::jsonb,
  next_reminder_at timestamptz,
  status public.assignment_status not null default 'assigned',
  started_at timestamptz,
  completed_at timestamptz,
  completion_response_id uuid references public.survey_responses(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (survey_version_id, user_id),
  constraint assignment_reminder_config_object check (jsonb_typeof(reminder_config) = 'object'),
  constraint assignment_completion_state check (
    (status = 'completed' and completed_at is not null)
    or (status <> 'completed')
  )
);

-- This mapping is never exposed through PostgREST. A pseudonym is stable within
-- one organization, but submit_survey_response only places it on responses from
-- survey versions that explicitly enable cross-survey pseudonymous linking.
create table private.organization_user_pseudonyms (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  pseudonym_id uuid not null default gen_random_uuid(),
  created_at timestamptz not null default now(),
  primary key (organization_id, user_id),
  unique (organization_id, pseudonym_id)
);

-- When cross-survey linking is disabled, keep a separate stable pseudonym for
-- each user and exact survey version. This mapping is private and cannot link
-- the same person across survey versions.
create table private.survey_version_user_pseudonyms (
  survey_version_id uuid not null references public.survey_versions(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  pseudonym_id uuid not null default gen_random_uuid(),
  created_at timestamptz not null default now(),
  primary key (survey_version_id, user_id),
  unique (survey_version_id, pseudonym_id)
);

-- Identified responses are linked here, rather than by a user-id column on the
-- response visible to API clients. Only the authorized response RPC joins it.
create table private.response_identities (
  response_id uuid primary key references public.survey_responses(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table private.response_deduplication (
  response_id uuid primary key references public.survey_responses(id) on delete cascade,
  survey_version_id uuid not null references public.survey_versions(id) on delete cascade,
  dedupe_key_hash text not null,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Response-upload paths are opaque and ownership stays outside the exposed API
-- schema. A finalized anonymous response clears the temporary account owner so
-- the stored response and file path do not preserve an application-level link.
create table private.response_upload_objects (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  survey_version_id uuid not null references public.survey_versions(id) on delete cascade,
  owner_user_id uuid references auth.users(id) on delete set null,
  response_id uuid references public.survey_responses(id) on delete cascade,
  bucket_id text not null default 'survey-response-uploads',
  object_path text not null unique,
  original_filename text not null,
  mime_type text not null,
  size_bytes bigint not null,
  checksum_sha256 text,
  created_at timestamptz not null default now(),
  attached_at timestamptz,
  constraint response_upload_bucket check (bucket_id = 'survey-response-uploads'),
  constraint response_upload_path_relative check (
    object_path !~ '^/' and object_path !~ '(^|/)\.\.(/|$)'
  ),
  constraint response_upload_size check (size_bytes between 1 and 52428800),
  constraint response_upload_attachment_state check (
    (response_id is null and attached_at is null)
    or (response_id is not null and attached_at is not null)
  )
);

create unique index one_active_dedupe_key
  on private.response_deduplication(survey_version_id, dedupe_key_hash)
  where active;

create table private.notification_outbox (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  event_type text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  available_at timestamptz not null default now(),
  processed_at timestamptz,
  attempt_count integer not null default 0,
  last_error text,
  constraint notification_outbox_payload_object check (jsonb_typeof(payload) = 'object'),
  constraint notification_outbox_attempts check (attempt_count >= 0)
);

create table public.organization_audit_log (
  id bigint generated always as identity primary key,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  actor_user_id uuid references auth.users(id) on delete set null,
  event_type text not null,
  object_type text not null,
  object_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint audit_log_details_object check (jsonb_typeof(details) = 'object')
);

-- ---------------------------------------------------------------------------
-- Indexes used by authorization, dashboards, and response reporting
-- ---------------------------------------------------------------------------

create index memberships_user_status_idx
  on public.organization_memberships(user_id, status, organization_id);
create index memberships_org_status_role_idx
  on public.organization_memberships(organization_id, status, role);
create index invitations_org_email_idx
  on public.organization_invitations(organization_id, email, expires_at);
create index join_codes_active_idx
  on public.organization_join_codes(organization_id, is_active, expires_at);
create index membership_requests_org_created_idx
  on public.membership_requests(organization_id, created_at desc);
create index map_assets_org_archived_idx
  on public.map_assets(organization_id, archived_at, created_at desc);
create index map_versions_asset_created_idx
  on public.map_versions(map_asset_id, version_number desc);
create index map_regions_version_idx on public.map_regions(map_version_id);
create index surveys_org_status_idx on public.surveys(organization_id, status, updated_at desc);
create index surveys_deletion_due_idx on public.surveys(deletion_due_at, id)
  where deleted_at is not null;
create index survey_versions_survey_idx on public.survey_versions(survey_id, version_number desc);
create index survey_questions_version_position_idx on public.survey_questions(survey_version_id, position);
create index survey_questions_map_version_idx on public.survey_questions(map_version_id) where map_version_id is not null;
create index survey_logic_version_idx on public.survey_logic_rules(survey_version_id, position);
create index responses_version_submitted_idx
  on public.survey_responses(survey_version_id, submitted_at desc)
  where status = 'submitted';
create index responses_org_submitted_idx
  on public.survey_responses(organization_id, submitted_at desc);
create index responses_pseudonym_idx
  on public.survey_responses(organization_id, pseudonym_id)
  where pseudonym_id is not null;
create index drafts_owner_updated_idx on public.response_drafts(owner_user_id, updated_at desc);
create index assignments_user_status_idx on public.survey_assignments(user_id, status, due_at);
create index assignments_org_status_idx on public.survey_assignments(organization_id, status, due_at);
create index audit_org_created_idx on public.organization_audit_log(organization_id, created_at desc);
create index outbox_pending_idx on private.notification_outbox(available_at, created_at)
  where processed_at is null;
create index response_upload_owner_pending_idx
  on private.response_upload_objects(owner_user_id, survey_version_id, created_at desc)
  where response_id is null;
create index response_upload_response_idx
  on private.response_upload_objects(response_id)
  where response_id is not null;

-- ---------------------------------------------------------------------------
-- Security helpers and invariant-preserving triggers
-- ---------------------------------------------------------------------------

create or replace function public.has_org_role(
  p_organization_id uuid,
  p_roles public.organization_role[]
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.organization_memberships m
    where m.organization_id = p_organization_id
      and m.user_id = auth.uid()
      and m.status = 'approved'
      and m.role = any (p_roles)
  );
$$;

create or replace function public.is_org_member(p_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.organization_memberships m
    where m.organization_id = p_organization_id
      and m.user_id = auth.uid()
      and m.status = 'approved'
  );
$$;

create or replace function public.can_access_survey_version(p_survey_version_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.survey_versions v
    join public.surveys s on s.id = v.survey_id
    where v.id = p_survey_version_id
      and v.status = 'published'
      and s.current_published_version_id = v.id
      and s.status = 'published'
      and s.deleted_at is null
      and (v.opens_at is null or v.opens_at <= pg_catalog.now())
      and (v.closes_at is null or v.closes_at > pg_catalog.now())
      and (
        v.access = 'open'
        or public.is_org_member(s.organization_id)
      )
  );
$$;

-- A respondent needs the organization name to understand who is asking the
-- questions even when the organization has not opted into a broader public
-- profile. The description and reusable slug remain hidden unless that opt-in
-- is enabled.
create or replace function public.get_survey_organization_display(p_survey_version_id uuid)
returns table (
  organization_id uuid,
  organization_name text,
  organization_slug text,
  organization_description text,
  public_profile_enabled boolean
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.can_access_survey_version(p_survey_version_id) then
    raise exception 'This survey organization is not available to this user.' using errcode = '42501';
  end if;

  return query
  select
    o.id,
    o.name,
    case when o.public_profile_enabled then o.slug else '' end,
    case when o.public_profile_enabled then o.description else '' end,
    o.public_profile_enabled
  from public.survey_versions sv
  join public.surveys s on s.id = sv.survey_id
  join public.organizations o on o.id = s.organization_id
  where sv.id = p_survey_version_id;
end;
$$;

-- Respondents may need the organization-owned public Mapbox token to render an
-- interactive map. Expose only the whitelisted browser configuration for the
-- exact survey version they can access; the integration row's identifiers,
-- secret reference, staff identity, and timestamps remain private.
create or replace function public.get_survey_mapbox_integration(p_survey_version_id uuid)
returns table (
  status public.integration_status,
  public_config jsonb
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.can_access_survey_version(p_survey_version_id) then
    raise exception 'This survey integration is not available to this user.' using errcode = '42501';
  end if;

  return query
  select
    i.status,
    case when i.status = 'connected' then
      pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'public_token', coalesce(i.public_config -> 'public_token', i.public_config -> 'publicToken'),
        'username', i.public_config -> 'username',
        'geocoding_enabled_by_default', coalesce(
          i.public_config -> 'geocoding_enabled_by_default',
          i.public_config -> 'geocodingEnabledByDefault'
        )
      ))
    else '{}'::pg_catalog.jsonb end
  from public.survey_versions sv
  join public.surveys s on s.id = sv.survey_id
  join public.organization_integrations i
    on i.organization_id = s.organization_id
   and i.provider = 'mapbox'
  where sv.id = p_survey_version_id
    and exists (
      select 1
      from public.survey_questions q
      join public.map_versions mv on mv.id = q.map_version_id
      where q.survey_version_id = sv.id
        and mv.source_kind = 'mapbox'
    );
end;
$$;

-- Public profiles are exposed through a column-limited RPC rather than the
-- organizations table, whose administrator identifiers must remain private.
create or replace function public.get_public_organization_profile(p_organization_slug text)
returns table (
  organization_id uuid,
  organization_name text,
  organization_slug text,
  organization_description text
)
language sql
stable
security definer
set search_path = ''
as $$
  select o.id, o.name, o.slug, o.description
  from public.organizations o
  where o.slug = lower(btrim(p_organization_slug))
    and o.public_profile_enabled;
$$;

-- Pending and rejected applicants may see the organization they requested to
-- join without receiving private administrator ids or unrelated org records.
create or replace function public.get_membership_organization_display(p_organization_id uuid)
returns table (
  organization_id uuid,
  organization_name text,
  organization_slug text,
  organization_description text,
  public_profile_enabled boolean
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not exists (
    select 1
    from public.organization_memberships m
    where m.organization_id = p_organization_id
      and m.user_id = auth.uid()
  ) then
    raise exception 'This membership organization is not available to this user.' using errcode = '42501';
  end if;

  return query
  select
    o.id,
    o.name,
    case when o.public_profile_enabled then o.slug else '' end,
    case when o.public_profile_enabled then o.description else '' end,
    o.public_profile_enabled
  from public.organizations o
  where o.id = p_organization_id;
end;
$$;

-- Email remains in auth.users. Only an approved owner or administrator can
-- retrieve account emails, and only for users with a membership in this exact
-- organization. This disambiguates same-name members without granting any
-- broad auth.users access.
create or replace function public.get_membership_account_identities(p_organization_id uuid)
returns table (
  user_id uuid,
  account_email text
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.has_org_role(
    p_organization_id,
    array['owner', 'admin']::public.organization_role[]
  ) then
    raise exception 'Only organization administrators can view member account emails.' using errcode = '42501';
  end if;

  return query
  select m.user_id, lower(u.email)
  from public.organization_memberships m
  join auth.users u on u.id = m.user_id
  where m.organization_id = p_organization_id
  order by m.created_at;
end;
$$;

create or replace function public.can_read_map_version(p_map_version_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.map_versions mv
    join public.map_assets ma on ma.id = mv.map_asset_id
    where mv.id = p_map_version_id
      and (
        ma.visibility = 'public'
        or public.has_org_role(
          ma.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
        or exists (
          select 1
          from public.survey_questions q
          where q.map_version_id = mv.id
            and public.can_access_survey_version(q.survey_version_id)
        )
      )
  );
$$;

create or replace function public.can_read_map_asset(p_map_asset_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.map_assets ma
    where ma.id = p_map_asset_id
      and (
        ma.visibility = 'public'
        or public.has_org_role(
          ma.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
        or exists (
          select 1
          from public.map_versions mv
          join public.survey_questions q on q.map_version_id = mv.id
          where mv.map_asset_id = ma.id
            and public.can_access_survey_version(q.survey_version_id)
        )
      )
  );
$$;

create or replace function public.storage_path_first_uuid(p_object_path text)
returns uuid
language plpgsql
immutable
set search_path = ''
as $$
begin
  return nullif(pg_catalog.split_part(p_object_path, '/', 1), '')::uuid;
exception when invalid_text_representation then
  return null;
end;
$$;

create or replace function public.can_manage_static_map_object(
  p_bucket_id text,
  p_object_path text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select p_bucket_id = 'survey-static-maps'
    and public.has_org_role(
      public.storage_path_first_uuid(p_object_path),
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
    and not exists (
      select 1 from public.map_versions mv
      where mv.static_bucket = p_bucket_id
        and mv.static_object_path = p_object_path
        and mv.locked_at is not null
    );
$$;

create or replace function public.can_read_static_map_object(
  p_bucket_id text,
  p_object_path text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.map_versions mv
    where mv.static_bucket = p_bucket_id
      and mv.static_object_path = p_object_path
      and public.can_read_map_version(mv.id)
  );
$$;

create or replace function public.can_write_response_upload_object(
  p_bucket_id text,
  p_object_path text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from private.response_upload_objects u
    where u.bucket_id = p_bucket_id
      and u.object_path = p_object_path
      and u.owner_user_id = auth.uid()
      and u.response_id is null
      and public.can_access_survey_version(u.survey_version_id)
  );
$$;

create or replace function public.can_read_response_upload_object(
  p_bucket_id text,
  p_object_path text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from private.response_upload_objects u
    where u.bucket_id = p_bucket_id
      and u.object_path = p_object_path
      and (
        u.owner_user_id = auth.uid()
        or (
          u.response_id is not null
          and public.has_org_role(
            u.organization_id,
            array['owner', 'admin', 'response_viewer']::public.organization_role[]
          )
        )
      )
  );
$$;

create or replace function public.can_delete_response_upload_object(
  p_bucket_id text,
  p_object_path text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from private.response_upload_objects u
    where u.bucket_id = p_bucket_id
      and u.object_path = p_object_path
      and (
        (u.owner_user_id = auth.uid() and u.response_id is null)
        or public.has_org_role(
          u.organization_id,
          array['owner', 'admin']::public.organization_role[]
        )
      )
  );
$$;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := pg_catalog.now();
  return new;
end;
$$;

create or replace function private.write_audit(
  p_organization_id uuid,
  p_event_type text,
  p_object_type text,
  p_object_id text default null,
  p_details jsonb default '{}'::jsonb
)
returns void
language sql
security definer
set search_path = ''
as $$
  insert into public.organization_audit_log (
    organization_id, actor_user_id, event_type, object_type, object_id, details
  ) values (
    p_organization_id, auth.uid(), p_event_type, p_object_type, p_object_id,
    coalesce(p_details, '{}'::jsonb)
  );
$$;

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    left(coalesce(new.raw_user_meta_data ->> 'display_name', new.raw_user_meta_data ->> 'name', ''), 160)
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_auth_user();

create or replace function public.guard_map_version_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if old.locked_at is not null then
    raise exception 'Map version % is locked because it is used by a published survey.', old.id
      using errcode = '55000';
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

create trigger guard_locked_map_versions
  before update or delete on public.map_versions
  for each row execute function public.guard_map_version_mutation();

create or replace function public.guard_locked_map_asset_visibility()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.visibility is distinct from old.visibility and exists (
    select 1 from public.map_versions mv
    where mv.map_asset_id = old.id and mv.locked_at is not null
  ) then
    raise exception 'Visibility for a map used by a published survey cannot be changed. Create a new map version or asset instead.'
      using errcode = '55000';
  end if;
  return new;
end;
$$;

create trigger guard_locked_map_asset_visibility
  before update of visibility on public.map_assets
  for each row execute function public.guard_locked_map_asset_visibility();

create or replace function public.guard_map_region_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_old_version_id uuid;
  v_new_version_id uuid;
  v_locked_at timestamptz;
begin
  if tg_op <> 'INSERT' then
    v_old_version_id := old.map_version_id;
    select mv.locked_at into v_locked_at
    from public.map_versions mv
    where mv.id = v_old_version_id;

    if v_locked_at is not null then
      raise exception 'Regions for locked map version % cannot be changed.', v_old_version_id
        using errcode = '55000';
    end if;
  end if;

  if tg_op <> 'DELETE' then
    v_new_version_id := new.map_version_id;
    select mv.locked_at into v_locked_at
    from public.map_versions mv
    where mv.id = v_new_version_id;

    if v_locked_at is not null then
      raise exception 'Regions for locked map version % cannot be changed.', v_new_version_id
        using errcode = '55000';
    end if;
  end if;

  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

create trigger guard_locked_map_regions
  before insert or update or delete on public.map_regions
  for each row execute function public.guard_map_region_mutation();

create or replace function public.guard_survey_identity_delete()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if old.deleted_at is null then
    raise exception 'Move a survey to Recently Deleted before permanent deletion.' using errcode = '55000';
  end if;
  if current_user not in ('postgres', 'supabase_admin') then
    raise exception 'Permanently delete surveys through the reviewed lifecycle purge function.' using errcode = '42501';
  end if;
  return old;
end;
$$;

create trigger guard_survey_identity_delete
  before delete on public.surveys
  for each row execute function public.guard_survey_identity_delete();

create or replace function public.guard_survey_version_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  -- A reviewed lifecycle purge deletes the parent survey identity. PostgreSQL
  -- then invokes this trigger for version rows through ON DELETE CASCADE. A
  -- direct version delete still sees its parent and remains forbidden.
  if tg_op = 'DELETE' and not exists (
    select 1 from public.surveys s where s.id = old.survey_id
  ) then
    return old;
  end if;
  if old.status = 'published' then
    raise exception 'Published survey version % is immutable. Create an editable copy instead.', old.id
      using errcode = '55000';
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

create trigger guard_published_survey_versions
  before update or delete on public.survey_versions
  for each row execute function public.guard_survey_version_mutation();

create or replace function public.assert_draft_survey_child()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_old_version_id uuid;
  v_new_version_id uuid;
  v_old_status public.survey_version_status;
  v_new_status public.survey_version_status;
begin
  if tg_op <> 'INSERT' then
    if tg_table_name = 'survey_question_options' then
      select q.survey_version_id into v_old_version_id
      from public.survey_questions q
      where q.id = old.question_id;
    else
      v_old_version_id := old.survey_version_id;
    end if;

    -- During the reviewed stable-survey purge, the survey identity has already
    -- been deleted and PostgreSQL is cascading through version children. A
    -- direct child delete still joins to its live survey and remains subject to
    -- immutable-version protection.
    if tg_op = 'DELETE' and not exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = v_old_version_id
    ) then
      return old;
    end if;

    select sv.status into v_old_status
    from public.survey_versions sv
    where sv.id = v_old_version_id;

    if v_old_status is distinct from 'draft'::public.survey_version_status then
      raise exception 'Published survey content is immutable. Create an editable copy instead.'
        using errcode = '55000';
    end if;
  end if;

  if tg_op <> 'DELETE' then
    if tg_table_name = 'survey_question_options' then
      select q.survey_version_id into v_new_version_id
      from public.survey_questions q
      where q.id = new.question_id;
    else
      v_new_version_id := new.survey_version_id;
    end if;

    select sv.status into v_new_status
    from public.survey_versions sv
    where sv.id = v_new_version_id;

    if v_new_status is distinct from 'draft'::public.survey_version_status then
      raise exception 'Published survey content is immutable. Create an editable copy instead.'
        using errcode = '55000';
    end if;
  end if;

  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

create trigger guard_survey_questions
  before insert or update or delete on public.survey_questions
  for each row execute function public.assert_draft_survey_child();
create trigger guard_survey_question_options
  before insert or update or delete on public.survey_question_options
  for each row execute function public.assert_draft_survey_child();
create trigger guard_survey_trigger_areas
  before insert or update or delete on public.survey_map_trigger_areas
  for each row execute function public.assert_draft_survey_child();
create trigger guard_survey_logic_rules
  before insert or update or delete on public.survey_logic_rules
  for each row execute function public.assert_draft_survey_child();
create trigger guard_survey_version_settings
  before insert or update or delete on public.survey_version_setting_values
  for each row execute function public.assert_draft_survey_child();

create or replace function public.validate_survey_question_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_survey_org uuid;
  v_map_org uuid;
begin
  if new.map_version_id is null then
    return new;
  end if;

  select s.organization_id into v_survey_org
  from public.survey_versions sv
  join public.surveys s on s.id = sv.survey_id
  where sv.id = new.survey_version_id;

  select ma.organization_id into v_map_org
  from public.map_versions mv
  join public.map_assets ma on ma.id = mv.map_asset_id
  where mv.id = new.map_version_id;

  if v_survey_org is null or v_map_org is null or v_survey_org <> v_map_org then
    raise exception 'A question can only use a map owned by the same organization.'
      using errcode = '23514';
  end if;
  return new;
end;
$$;

create trigger validate_question_map_scope
  before insert or update on public.survey_questions
  for each row execute function public.validate_survey_question_scope();

create or replace function public.validate_logic_rule_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_source_version uuid;
  v_target_version uuid;
  v_area_version uuid;
  v_source_type public.question_type;
  v_source_map_version uuid;
  v_area_map_version uuid;
begin
  select q.survey_version_id, q.type, q.map_version_id
  into v_source_version, v_source_type, v_source_map_version
  from public.survey_questions q where q.id = new.source_question_id;
  select q.survey_version_id into v_target_version
  from public.survey_questions q where q.id = new.target_question_id;

  if v_source_version is distinct from new.survey_version_id
     or v_target_version is distinct from new.survey_version_id then
    raise exception 'Logic source and target questions must belong to the same survey version.'
      using errcode = '23514';
  end if;

  if new.trigger_area_id is not null then
    select a.survey_version_id, a.map_version_id into v_area_version, v_area_map_version
    from public.survey_map_trigger_areas a where a.id = new.trigger_area_id;
    if v_area_version is distinct from new.survey_version_id then
      raise exception 'A logic trigger area must belong to the same survey version.'
        using errcode = '23514';
    end if;
    if v_source_type not in ('map_markup', 'map_polygon')
       or v_source_map_version is distinct from v_area_map_version then
      raise exception 'Drawing logic must compare a drawing question with a trigger area on that question’s map version.'
        using errcode = '23514';
    end if;
  elsif new.operator in (
    'selected_region', 'selected_region_count_at_least', 'selected_region_count_at_most'
  ) and v_source_type <> 'map_tiles' then
    raise exception 'Region-selection logic requires a tile-selection source question.'
      using errcode = '23514';
  end if;
  return new;
end;
$$;

create trigger validate_logic_rule_scope
  before insert or update on public.survey_logic_rules
  for each row execute function public.validate_logic_rule_scope();

create or replace function public.validate_trigger_area_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_survey_org uuid;
  v_map_org uuid;
begin
  select s.organization_id into v_survey_org
  from public.survey_versions sv
  join public.surveys s on s.id = sv.survey_id
  where sv.id = new.survey_version_id;
  select ma.organization_id into v_map_org
  from public.map_versions mv
  join public.map_assets ma on ma.id = mv.map_asset_id
  where mv.id = new.map_version_id;

  if v_survey_org is null or v_map_org is null or v_survey_org <> v_map_org then
    raise exception 'A trigger area can only use a map owned by the same organization.'
      using errcode = '23514';
  end if;
  return new;
end;
$$;

create trigger validate_trigger_area_scope
  before insert or update on public.survey_map_trigger_areas
  for each row execute function public.validate_trigger_area_scope();

create or replace function public.validate_survey_current_versions()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.current_draft_version_id is not null and not exists (
    select 1 from public.survey_versions sv
    where sv.id = new.current_draft_version_id
      and sv.survey_id = new.id
      and sv.status = 'draft'
  ) then
    raise exception 'Current draft version must be a draft belonging to this survey.'
      using errcode = '23514';
  end if;

  if new.current_published_version_id is not null and not exists (
    select 1 from public.survey_versions sv
    where sv.id = new.current_published_version_id
      and sv.survey_id = new.id
      and sv.status = 'published'
  ) then
    raise exception 'Current published version must be published and belong to this survey.'
      using errcode = '23514';
  end if;
  return new;
end;
$$;

create constraint trigger validate_survey_current_versions
  after insert or update of current_draft_version_id, current_published_version_id
  on public.surveys
  deferrable initially deferred
  for each row execute function public.validate_survey_current_versions();

create or replace function public.validate_setting_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_scope public.setting_scope;
begin
  select d.scope into v_scope
  from public.setting_definitions d where d.key = new.setting_key;

  if tg_table_name = 'organization_setting_values' and v_scope <> 'organization' then
    raise exception 'Setting % is not an organization setting.', new.setting_key using errcode = '23514';
  elsif tg_table_name = 'survey_version_setting_values' and v_scope <> 'survey' then
    raise exception 'Setting % is not a survey setting.', new.setting_key using errcode = '23514';
  end if;
  return new;
end;
$$;

create trigger validate_organization_setting_scope
  before insert or update on public.organization_setting_values
  for each row execute function public.validate_setting_scope();
create trigger validate_survey_setting_scope
  before insert or update on public.survey_version_setting_values
  for each row execute function public.validate_setting_scope();

create or replace function public.validate_assignment_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if not exists (
    select 1
    from public.survey_versions sv
    join public.surveys s on s.id = sv.survey_id
    where sv.id = new.survey_version_id
      and sv.survey_id = new.survey_id
      and s.organization_id = new.organization_id
      and sv.status = 'published'
      and s.status = 'published'
      and s.current_published_version_id = sv.id
  ) then
    raise exception 'Assignments must target the current immutable published version of the matching organization and survey.' using errcode = '23514';
  end if;
  if not exists (
    select 1 from public.organization_memberships m
    where m.organization_id = new.organization_id
      and m.user_id = new.user_id
      and m.status = 'approved'
  ) then
    raise exception 'Assignments may only be made to approved organization members.' using errcode = '23514';
  end if;
  return new;
end;
$$;

create trigger validate_assignment_scope
  before insert or update on public.survey_assignments
  for each row execute function public.validate_assignment_scope();

create or replace function public.validate_response_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if not exists (
    select 1
    from public.survey_versions sv
    join public.surveys s on s.id = sv.survey_id
    where sv.id = new.survey_version_id
      and sv.survey_id = new.survey_id
      and s.organization_id = new.organization_id
      and sv.privacy = new.privacy
  ) then
    raise exception 'Response organization, survey, version, or privacy snapshot does not match.'
      using errcode = '23514';
  end if;
  return new;
end;
$$;

create trigger validate_response_scope
  before insert on public.survey_responses
  for each row execute function public.validate_response_scope();

create or replace function public.guard_submitted_response_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    -- Permit only a parent-survey cascade initiated by a reviewed
    -- security-definer lifecycle RPC. Direct response deletion still finds the
    -- parent survey and is rejected below.
    if not exists (
      select 1 from public.surveys s where s.id = old.survey_id
    ) then
      return old;
    end if;
    raise exception 'Submitted responses cannot be deleted directly; apply the retention or withdrawal workflow.'
      using errcode = '55000';
  end if;

  if new.id is distinct from old.id
     or new.organization_id is distinct from old.organization_id
     or new.survey_id is distinct from old.survey_id
     or new.survey_version_id is distinct from old.survey_version_id
     or new.privacy is distinct from old.privacy
     or new.pseudonym_id is distinct from old.pseudonym_id
     or new.answers is distinct from old.answers
     or new.started_at is distinct from old.started_at
     or new.submitted_at is distinct from old.submitted_at
     or new.metadata is distinct from old.metadata then
    raise exception 'Submitted response content and identity classification are immutable.'
      using errcode = '55000';
  end if;
  return new;
end;
$$;

create trigger guard_submitted_response_mutation
  before update or delete on public.survey_responses
  for each row execute function public.guard_submitted_response_mutation();

create or replace function public.guard_membership_role_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.organization_id <> old.organization_id or new.user_id <> old.user_id then
    raise exception 'Membership organization and user cannot be changed.' using errcode = '55000';
  end if;

  if (
       (new.role = 'owner' and new.status = 'approved')
       or (old.role = 'owner' and old.status = 'approved')
     )
     and not public.has_org_role(
       old.organization_id,
       array['owner']::public.organization_role[]
     ) then
    raise exception 'Only an organization owner can add or remove another owner.' using errcode = '42501';
  end if;

  if old.role = 'owner' and old.status = 'approved'
     and (new.role <> 'owner' or new.status <> 'approved')
     and not exists (
       select 1 from public.organization_memberships m
       where m.organization_id = old.organization_id
         and m.role = 'owner'
         and m.status = 'approved'
         and m.id <> old.id
     ) then
    raise exception 'An organization must retain at least one approved owner.' using errcode = '23514';
  end if;
  return new;
end;
$$;

create trigger guard_membership_role_change
  before update on public.organization_memberships
  for each row execute function public.guard_membership_role_change();

create trigger profiles_set_updated_at before update on public.profiles
  for each row execute function public.set_updated_at();
create trigger organizations_set_updated_at before update on public.organizations
  for each row execute function public.set_updated_at();
create trigger memberships_set_updated_at before update on public.organization_memberships
  for each row execute function public.set_updated_at();
create trigger integrations_set_updated_at before update on public.organization_integrations
  for each row execute function public.set_updated_at();
create trigger github_repositories_set_updated_at before update on public.organization_github_repositories
  for each row execute function public.set_updated_at();
create trigger map_assets_set_updated_at before update on public.map_assets
  for each row execute function public.set_updated_at();
create trigger surveys_set_updated_at before update on public.surveys
  for each row execute function public.set_updated_at();
create trigger survey_versions_set_updated_at before update on public.survey_versions
  for each row execute function public.set_updated_at();
create trigger response_drafts_set_updated_at before update on public.response_drafts
  for each row execute function public.set_updated_at();
create trigger assignments_set_updated_at before update on public.survey_assignments
  for each row execute function public.set_updated_at();

-- The UI can render these descriptions next to controls. They are deliberately
-- visible prose rather than tooltip-only copy.
insert into public.setting_definitions (
  key, scope, label, help_text, who_is_affected, consequences,
  editable_after_publish, requires_confirmation, default_value, validation_schema
) values
  ('organization.public-profile', 'organization', 'Public organization profile',
   'Allows the organization name and description to appear in public organization-profile surfaces beyond a specific survey.',
   'Anyone browsing public organization information.',
   'Off is the privacy-preserving default. Published survey participants still see the organization name needed to identify who is asking the questions, but not the reusable profile description or slug.',
   true, false, 'false', '{"type":"boolean"}'),
  ('organization.join-codes', 'organization', 'Organization join codes',
   'Lets people request membership with a code that administrators can rotate, limit, expire, or disable.',
   'Prospective members and organization administrators.',
   'By default a valid code creates a pending request. Administrators can explicitly configure a code to approve members immediately.',
   true, true, 'false', '{"type":"boolean"}'),
  ('organization.membership-notifications', 'organization', 'Membership request notifications',
   'Chooses who receives an email when someone requests to join. The primary administrator is the default.',
   'Configured recipients and prospective members.',
   'If no recipient is active, requests still appear on the dashboard but no email is sent.',
   true, false, '[]', '{"type":"array"}'),
  ('survey.access', 'survey', 'Who can open this survey',
   'Open surveys accept anyone with the link. Member-only surveys require an approved organization login.',
   'Every potential respondent.',
   'Changing access on an editable copy does not change access to earlier published versions.',
   false, true, '"open"', '{"enum":["open","members"]}'),
  ('survey.privacy', 'survey', 'How respondent identity is recorded',
   'Anonymous stores no account link; pseudonymous stores an opaque identifier; identified allows authorized viewers to see the respondent account.',
   'Respondents and authorized response viewers.',
   'The selected privacy mode is frozen when this version is published.',
   false, true, '"anonymous"', '{"enum":["anonymous","pseudonymous","identified"]}'),
  ('survey.pseudonymous-linking', 'survey', 'Link pseudonymous responses across surveys',
   'Uses the same opaque identifier for this signed-in person on other surveys in this organization that also enable linking.',
   'Signed-in pseudonymous respondents and response analysts.',
   'It does not link to identified responses and the app provides no re-identification path.',
   false, true, 'false', '{"type":"boolean"}'),
  ('survey.duplicate-policy', 'survey', 'Duplicate response policy',
   'Controls whether the survey accepts repeated submissions by an account or browser device.',
   'Every respondent.',
   'Device-based limits can be bypassed by clearing browser data; account-based limits require login and are unavailable for anonymous surveys.',
   false, true, '"allow"', '{"enum":["allow","one_per_account","one_per_device","replace_previous"]}'),
  ('survey.save-resume', 'survey', 'Save and resume across devices',
   'Stores a signed-in respondent’s unfinished draft so they can continue after logging in on another device.',
   'Signed-in respondents only.',
   'Open anonymous visitors keep progress only in their current browser; no anonymous server draft is created.',
   false, false, 'true', '{"type":"boolean"}'),
  ('survey.schedule', 'survey', 'Open and close dates',
   'Automatically makes the published survey available during a configured time window.',
   'Every potential respondent.',
   'Outside the window, new submissions are rejected by the database.',
   false, false, 'null', '{"type":["object","null"]}'),
  ('survey.response-limit', 'survey', 'Response limit',
   'Stops accepting new responses after the specified number of active submissions.',
   'Every potential respondent.',
   'Once the limit is reached, the database rejects additional submissions.',
   false, true, 'null', '{"type":["integer","null"],"minimum":1}'),
  ('survey.retention', 'survey', 'Response retention',
   'Defines how long submitted data should be retained before an authorized deletion job removes or de-identifies it.',
   'Respondents, administrators, and response viewers.',
   'A scheduled retention worker is required; saving this setting alone does not run deletion jobs.',
   false, true, 'null', '{"type":["integer","null"],"minimum":1}'),
  ('survey.conditional-logic', 'survey', 'Conditional logic',
   'Shows, hides, or requires follow-up questions based on earlier answers or carefully defined map-area tests.',
   'Respondents taking this survey.',
   'Map drawing rules should be previewed against named trigger areas before publishing.',
   false, false, '[]', '{"type":"array"}'),
  ('survey.assignments', 'survey', 'Assignments',
   'Lets survey managers assign this survey to approved members and optionally set due dates.',
   'Assigned members and survey managers.',
   'Assignment completion can be recorded without revealing which anonymous or pseudonymous response belongs to the member.',
   true, false, 'false', '{"type":"boolean"}'),
  ('survey.reminders', 'survey', 'Assignment reminders',
   'Schedules reminder emails for incomplete assignments according to the configured cadence.',
   'Assigned members and configured notification senders.',
   'A scheduled worker must be running; enabling this setting alone does not send email.',
   true, false, '{}', '{"type":"object"}'),
  ('survey.completion-message', 'survey', 'Completion message',
   'Sets the confirmation respondents see after a successful submission.',
   'Every respondent who submits this survey.',
   'The message is frozen for this version when it is published.',
   false, false, '"Thank you for your response."', '{"type":"string","maxLength":4000}'),
  ('survey.notifications', 'survey', 'Survey activity notifications',
   'Chooses whether authorized organization recipients are notified about configured survey events.',
   'Configured recipients and survey administrators.',
   'Notifications can expose activity timing, so recipients should be limited to people who need it.',
   false, false, '{}', '{"type":"object"}'),
  ('map.visibility', 'map', 'Map visibility',
   'Public map files can be delivered to anyone. Restricted map files require a survey or organization access check.',
   'Survey respondents and organization map managers.',
   'Changing a map to public can expose the underlying image or tiles beyond a single survey.',
   true, true, '"restricted"', '{"enum":["public","restricted"]}'),
  ('map.bounds', 'map', 'Geographic map bounds',
   'Optionally links the edges of a static image to longitude and latitude so drawings can align with GIS data.',
   'Map managers and analysts exporting geographic results.',
   'Without bounds, drawings remain in normalized image coordinates. A used map version cannot be retroactively changed.',
   true, false, 'null', '{"type":["object","null"]}'),
  ('map.regions', 'map', 'Selectable map regions',
   'Optionally defines uploaded, rectangular, hexagonal, or manually drawn regions for tile-selection questions.',
   'Survey builders and respondents answering tile-selection questions.',
   'Tile selection is unavailable until the selected map version contains regions.',
   true, false, '"none"', '{"enum":["none","rectangular_grid","hex_grid","uploaded","manual"]}'),
  ('map.geocoding', 'map', 'Address and landmark search',
   'Enables Mapbox-powered address or landmark search for this Mapbox map version.',
   'Respondents using questions that reference this map.',
   'Search sends the entered query to Mapbox and becomes unavailable if Mapbox is disconnected.',
   true, false, 'false', '{"type":"boolean"}'),
  ('integration.github', 'integration', 'GitHub connection',
   'Connects the organization-owned repository used for the interface, Pages deployment, and optional tileset workflow.',
   'Organization administrators and everyone who visits the deployed site.',
   'Disconnecting stops automated repository and deployment operations but does not delete the repository.',
   true, true, 'null', '{"type":["object","null"]}'),
  ('integration.supabase', 'integration', 'Supabase project',
   'Connects the organization-owned authentication, database, and private file-storage project.',
   'All organization users and respondents.',
   'Changing projects changes where accounts and responses live; this requires an explicit migration plan.',
   true, true, 'null', '{"type":["object","null"]}'),
  ('integration.mapbox', 'integration', 'Mapbox connection',
   'Enables optional interactive Mapbox maps, tilesets, and geocoding for questions that select them.',
   'Respondents using Mapbox-backed questions and map managers.',
   'Disconnecting makes every Mapbox-backed question unavailable; no static fallback is inserted.',
   true, true, 'null', '{"type":["object","null"]}')
on conflict (key) do update set
  scope = excluded.scope,
  label = excluded.label,
  help_text = excluded.help_text,
  who_is_affected = excluded.who_is_affected,
  consequences = excluded.consequences,
  editable_after_publish = excluded.editable_after_publish,
  requires_confirmation = excluded.requires_confirmation,
  default_value = excluded.default_value,
  validation_schema = excluded.validation_schema;

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

alter table public.profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.organization_memberships enable row level security;
alter table public.organization_notification_recipients enable row level security;
alter table public.organization_invitations enable row level security;
alter table public.organization_join_codes enable row level security;
alter table public.membership_requests enable row level security;
alter table public.organization_integrations enable row level security;
alter table public.organization_github_repositories enable row level security;
alter table public.setting_definitions enable row level security;
alter table public.organization_setting_values enable row level security;
alter table public.map_assets enable row level security;
alter table public.map_versions enable row level security;
alter table public.map_regions enable row level security;
alter table public.surveys enable row level security;
alter table public.survey_versions enable row level security;
alter table public.survey_version_setting_values enable row level security;
alter table public.survey_questions enable row level security;
alter table public.survey_question_options enable row level security;
alter table public.survey_map_trigger_areas enable row level security;
alter table public.survey_logic_rules enable row level security;
alter table public.survey_responses enable row level security;
alter table public.response_drafts enable row level security;
alter table public.survey_assignments enable row level security;
alter table public.organization_audit_log enable row level security;

create policy profiles_select_self_or_staff
  on public.profiles for select to authenticated
  using (
    id = auth.uid()
    or exists (
      select 1
      from public.organization_memberships target_membership
      where target_membership.user_id = profiles.id
        and public.has_org_role(
          target_membership.organization_id,
          array['owner', 'admin']::public.organization_role[]
        )
    )
  );

create policy profiles_update_self
  on public.profiles for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

create policy organizations_select_member
  on public.organizations for select to authenticated
  using (public.is_org_member(id));

create policy organizations_update_admin
  on public.organizations for update to authenticated
  using (public.has_org_role(id, array['owner', 'admin']::public.organization_role[]))
  with check (public.has_org_role(id, array['owner', 'admin']::public.organization_role[]));

create policy memberships_select_self_or_admin
  on public.organization_memberships for select to authenticated
  using (
    user_id = auth.uid()
    or public.has_org_role(
      organization_id,
      array['owner', 'admin']::public.organization_role[]
    )
  );

create policy memberships_update_admin
  on public.organization_memberships for update to authenticated
  using (
    public.has_org_role(
      organization_id,
      array['owner', 'admin']::public.organization_role[]
    )
  )
  with check (
    public.has_org_role(
      organization_id,
      array['owner', 'admin']::public.organization_role[]
    )
  );

create policy notification_recipients_admin_all
  on public.organization_notification_recipients for all to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]))
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]));

create policy invitations_admin_select
  on public.organization_invitations for select to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]));

create policy join_codes_admin_select
  on public.organization_join_codes for select to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]));

create policy membership_requests_select_self_or_admin
  on public.membership_requests for select to authenticated
  using (
    user_id = auth.uid()
    or public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[])
  );

create policy integrations_admin_all
  on public.organization_integrations for all to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]))
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]));

create policy github_repositories_admin_all
  on public.organization_github_repositories for all to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]))
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]));

create policy setting_definitions_read_all
  on public.setting_definitions for select to anon, authenticated
  using (true);

create policy organization_settings_admin_all
  on public.organization_setting_values for all to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]))
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]));

create policy map_assets_read_when_allowed
  on public.map_assets for select to anon, authenticated
  using (public.can_read_map_asset(id));

create policy map_assets_manage_staff
  on public.map_assets for all to authenticated
  using (
    public.has_org_role(
      organization_id,
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
  )
  with check (
    public.has_org_role(
      organization_id,
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
  );

create policy map_versions_read_when_allowed
  on public.map_versions for select to anon, authenticated
  using (public.can_read_map_version(id));

create policy map_versions_manage_staff
  on public.map_versions for all to authenticated
  using (
    exists (
      select 1 from public.map_assets ma
      where ma.id = map_versions.map_asset_id
        and public.has_org_role(
          ma.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  )
  with check (
    exists (
      select 1 from public.map_assets ma
      where ma.id = map_versions.map_asset_id
        and public.has_org_role(
          ma.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy map_regions_read_when_allowed
  on public.map_regions for select to anon, authenticated
  using (public.can_read_map_version(map_version_id));

create policy map_regions_manage_staff
  on public.map_regions for all to authenticated
  using (
    exists (
      select 1
      from public.map_versions mv
      join public.map_assets ma on ma.id = mv.map_asset_id
      where mv.id = map_regions.map_version_id
        and public.has_org_role(
          ma.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  )
  with check (
    exists (
      select 1
      from public.map_versions mv
      join public.map_assets ma on ma.id = mv.map_asset_id
      where mv.id = map_regions.map_version_id
        and public.has_org_role(
          ma.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy surveys_read_staff_or_active_respondent
  on public.surveys for select to anon, authenticated
  using (
    public.has_org_role(
      organization_id,
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
    or (
      current_published_version_id is not null
      and public.can_access_survey_version(current_published_version_id)
    )
  );

create policy surveys_manage_staff
  on public.surveys for all to authenticated
  using (
    public.has_org_role(
      organization_id,
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
  )
  with check (
    public.has_org_role(
      organization_id,
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
  );

create policy survey_versions_read_staff_or_respondent
  on public.survey_versions for select to anon, authenticated
  using (
    public.can_access_survey_version(id)
    or exists (
      select 1
      from public.surveys s
      where s.id = survey_versions.survey_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy survey_versions_manage_staff
  on public.survey_versions for all to authenticated
  using (
    exists (
      select 1 from public.surveys s
      where s.id = survey_versions.survey_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  )
  with check (
    exists (
      select 1 from public.surveys s
      where s.id = survey_versions.survey_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy survey_version_settings_read_allowed
  on public.survey_version_setting_values for select to anon, authenticated
  using (
    public.can_access_survey_version(survey_version_id)
    or exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_version_setting_values.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy survey_version_settings_manage_staff
  on public.survey_version_setting_values for all to authenticated
  using (
    exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_version_setting_values.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  )
  with check (
    exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_version_setting_values.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy survey_questions_read_allowed
  on public.survey_questions for select to anon, authenticated
  using (
    public.can_access_survey_version(survey_version_id)
    or exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_questions.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy survey_questions_manage_staff
  on public.survey_questions for all to authenticated
  using (
    exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_questions.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  )
  with check (
    exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_questions.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy survey_options_read_allowed
  on public.survey_question_options for select to anon, authenticated
  using (
    exists (
      select 1 from public.survey_questions q
      where q.id = survey_question_options.question_id
        and (
          public.can_access_survey_version(q.survey_version_id)
          or exists (
            select 1
            from public.survey_versions sv
            join public.surveys s on s.id = sv.survey_id
            where sv.id = q.survey_version_id
              and public.has_org_role(
                s.organization_id,
                array['owner', 'admin', 'survey_manager']::public.organization_role[]
              )
          )
        )
    )
  );

create policy survey_options_manage_staff
  on public.survey_question_options for all to authenticated
  using (
    exists (
      select 1
      from public.survey_questions q
      join public.survey_versions sv on sv.id = q.survey_version_id
      join public.surveys s on s.id = sv.survey_id
      where q.id = survey_question_options.question_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  )
  with check (
    exists (
      select 1
      from public.survey_questions q
      join public.survey_versions sv on sv.id = q.survey_version_id
      join public.surveys s on s.id = sv.survey_id
      where q.id = survey_question_options.question_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy trigger_areas_read_allowed
  on public.survey_map_trigger_areas for select to anon, authenticated
  using (
    public.can_access_survey_version(survey_version_id)
    or exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_map_trigger_areas.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy trigger_areas_manage_staff
  on public.survey_map_trigger_areas for all to authenticated
  using (
    exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_map_trigger_areas.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  )
  with check (
    exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_map_trigger_areas.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy logic_rules_read_allowed
  on public.survey_logic_rules for select to anon, authenticated
  using (
    public.can_access_survey_version(survey_version_id)
    or exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_logic_rules.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy logic_rules_manage_staff
  on public.survey_logic_rules for all to authenticated
  using (
    exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_logic_rules.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  )
  with check (
    exists (
      select 1
      from public.survey_versions sv
      join public.surveys s on s.id = sv.survey_id
      where sv.id = survey_logic_rules.survey_version_id
        and public.has_org_role(
          s.organization_id,
          array['owner', 'admin', 'survey_manager']::public.organization_role[]
        )
    )
  );

create policy responses_read_authorized
  on public.survey_responses for select to authenticated
  using (
    public.has_org_role(
      organization_id,
      array['owner', 'admin', 'response_viewer']::public.organization_role[]
    )
  );

create policy drafts_owner_all
  on public.response_drafts for all to authenticated
  using (owner_user_id = auth.uid())
  with check (
    owner_user_id = auth.uid()
    and public.can_access_survey_version(survey_version_id)
    and exists (
      select 1 from public.survey_versions sv
      where sv.id = response_drafts.survey_version_id
        and sv.allow_save_and_resume
    )
  );

create policy assignments_read_assignee_or_staff
  on public.survey_assignments for select to authenticated
  using (
    user_id = auth.uid()
    or public.has_org_role(
      organization_id,
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
  );

create policy assignments_manage_staff
  on public.survey_assignments for all to authenticated
  using (
    public.has_org_role(
      organization_id,
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
  )
  with check (
    public.has_org_role(
      organization_id,
      array['owner', 'admin', 'survey_manager']::public.organization_role[]
    )
  );

create policy audit_log_read_admin
  on public.organization_audit_log for select to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.organization_role[]));

-- ---------------------------------------------------------------------------
-- Transactional RPCs
-- ---------------------------------------------------------------------------

create or replace function public.create_organization(
  p_name text,
  p_slug text,
  p_description text default '',
  p_github_owner text default null,
  p_github_repository text default null,
  p_expected_pages_url text default null
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_organization_id uuid;
  v_email text;
  v_github_owner text := nullif(btrim(p_github_owner), '');
  v_github_repository text := nullif(btrim(p_github_repository), '');
  v_expected_pages_url text := nullif(btrim(p_expected_pages_url), '');
begin
  if v_user_id is null then
    raise exception 'You must be signed in to create an organization.' using errcode = '42501';
  end if;
  if (v_github_owner is null) <> (v_github_repository is null) then
    raise exception 'GitHub owner and repository must be provided together or both left blank.' using errcode = '22023';
  end if;
  if v_expected_pages_url is not null and v_github_owner is null then
    raise exception 'An expected GitHub Pages URL requires a GitHub owner and repository.' using errcode = '22023';
  end if;
  if v_expected_pages_url is not null
     and v_expected_pages_url !~ '^https://[^[:space:]]+$' then
    raise exception 'Expected GitHub Pages URL must be an HTTPS URL.' using errcode = '22023';
  end if;

  insert into public.profiles (id, display_name)
  values (v_user_id, '')
  on conflict (id) do nothing;

  insert into public.organizations (
    name, slug, description, primary_admin_id, created_by
  ) values (
    btrim(p_name), lower(btrim(p_slug)), coalesce(p_description, ''), v_user_id, v_user_id
  )
  returning id into v_organization_id;

  insert into public.organization_memberships (
    organization_id, user_id, role, status, joined_via, approved_by, approved_at
  ) values (
    v_organization_id, v_user_id, 'owner', 'approved', 'created_organization', v_user_id, pg_catalog.now()
  );

  if v_github_owner is not null then
    insert into public.organization_github_repositories (
      organization_id, owner_login, repository_name, pages_enabled, pages_url, connected_by
    ) values (
      v_organization_id, v_github_owner, v_github_repository, false,
      v_expected_pages_url, v_user_id
    );
  end if;

  select lower(u.email) into v_email from auth.users u where u.id = v_user_id;
  if v_email is not null then
    insert into public.organization_notification_recipients (
      organization_id, email, receives_membership_requests, receives_survey_activity
    ) values (v_organization_id, v_email, true, true);
  end if;

  perform private.write_audit(
    v_organization_id, 'organization.created', 'organization', v_organization_id::text,
    pg_catalog.jsonb_build_object(
      'name', btrim(p_name),
      'slug', lower(btrim(p_slug)),
      'github_repository', case when v_github_owner is null then null
        else v_github_owner || '/' || v_github_repository end
    )
  );
  return v_organization_id;
end;
$$;

create or replace function public.create_organization_invitation(
  p_organization_id uuid,
  p_email text,
  p_requested_role public.organization_role default 'member'
)
returns table (invitation_id uuid, raw_token text, expires_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_token text;
  v_hash text;
  v_invitation_id uuid;
  v_expires_at timestamptz;
begin
  if not public.has_org_role(
    p_organization_id,
    array['owner', 'admin']::public.organization_role[]
  ) then
    raise exception 'Only organization administrators can create invitations.' using errcode = '42501';
  end if;
  if p_requested_role = 'owner' and not public.has_org_role(
    p_organization_id,
    array['owner']::public.organization_role[]
  ) then
    raise exception 'Only an owner can invite another owner.' using errcode = '42501';
  end if;
  v_token := pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  v_hash := pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(v_token, 'UTF8'), 'sha256'), 'hex'
  );
  v_expires_at := pg_catalog.now() + interval '3 days';

  insert into public.organization_invitations (
    organization_id, email, requested_role, token_hash, expires_at, created_by
  ) values (
    p_organization_id, lower(btrim(p_email)), p_requested_role, v_hash, v_expires_at, auth.uid()
  ) returning id into v_invitation_id;

  perform private.write_audit(
    p_organization_id, 'invitation.created', 'organization_invitation', v_invitation_id::text,
    pg_catalog.jsonb_build_object('email', lower(btrim(p_email)), 'role', p_requested_role)
  );

  -- Deliver this token immediately from a trusted Edge Function. It is not
  -- recoverable from the database after this call returns.
  return query select v_invitation_id, v_token, v_expires_at;
end;
$$;

create or replace function public.accept_organization_invitation(p_raw_token text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_user_email text;
  v_token_hash text;
  v_invitation public.organization_invitations%rowtype;
  v_membership_id uuid;
begin
  if v_user_id is null then
    raise exception 'Sign in before accepting an invitation.' using errcode = '42501';
  end if;
  v_token_hash := pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_raw_token, 'UTF8'), 'sha256'), 'hex'
  );

  select i.* into v_invitation
  from public.organization_invitations i
  where i.token_hash = v_token_hash
  for update;

  if not found
     or v_invitation.revoked_at is not null
     or v_invitation.accepted_at is not null
     or v_invitation.expires_at <= pg_catalog.now() then
    raise exception 'This invitation is invalid, expired, revoked, or already used.' using errcode = '22023';
  end if;

  select lower(u.email) into v_user_email from auth.users u where u.id = v_user_id;
  if v_user_email is distinct from v_invitation.email then
    raise exception 'Sign in with the email address that received this invitation.' using errcode = '42501';
  end if;

  insert into public.organization_memberships (
    organization_id, user_id, role, status, joined_via
  ) values (
    v_invitation.organization_id, v_user_id, v_invitation.requested_role, 'pending', 'invitation'
  )
  on conflict (organization_id, user_id) do update set
    role = case
      when public.organization_memberships.status = 'approved' then public.organization_memberships.role
      else excluded.role
    end,
    status = case
      when public.organization_memberships.status = 'approved' then 'approved'::public.membership_status
      else 'pending'::public.membership_status
    end,
    joined_via = 'invitation',
    approved_by = case
      when public.organization_memberships.status = 'approved' then public.organization_memberships.approved_by
      else null
    end,
    approved_at = case
      when public.organization_memberships.status = 'approved' then public.organization_memberships.approved_at
      else null
    end
  returning id into v_membership_id;

  update public.organization_invitations
  set accepted_by = v_user_id, accepted_at = pg_catalog.now()
  where id = v_invitation.id;

  insert into public.membership_requests (
    organization_id, membership_id, user_id, invitation_id
  ) values (
    v_invitation.organization_id, v_membership_id, v_user_id, v_invitation.id
  )
  on conflict (membership_id) do update set
    invitation_id = excluded.invitation_id,
    join_code_id = null,
    reviewed_by = null,
    reviewed_at = null,
    created_at = pg_catalog.now();

  insert into private.notification_outbox (organization_id, event_type, payload)
  values (
    v_invitation.organization_id,
    'membership.requested',
    pg_catalog.jsonb_build_object('membership_id', v_membership_id, 'method', 'invitation')
  );

  return v_membership_id;
end;
$$;

create or replace function public.rotate_organization_join_code(
  p_organization_id uuid,
  p_label text default 'Organization join code',
  p_raw_code text default null,
  p_expires_at timestamptz default null,
  p_max_uses integer default null,
  p_disable_existing boolean default true,
  p_approval_required boolean default true
)
returns table (join_code_id uuid, raw_code text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_code text;
  v_hash text;
  v_join_code_id uuid;
begin
  if not public.has_org_role(
    p_organization_id,
    array['owner', 'admin']::public.organization_role[]
  ) then
    raise exception 'Only organization administrators can rotate join codes.' using errcode = '42501';
  end if;
  if p_expires_at is not null and p_expires_at <= pg_catalog.now() then
    raise exception 'Join-code expiration must be in the future.' using errcode = '22023';
  end if;
  if p_max_uses is not null and p_max_uses < 1 then
    raise exception 'Maximum uses must be at least one.' using errcode = '22023';
  end if;

  v_code := upper(btrim(coalesce(
    nullif(p_raw_code, ''),
    pg_catalog.encode(extensions.gen_random_bytes(6), 'hex')
  )));
  if char_length(v_code) < 8 or char_length(v_code) > 64 then
    raise exception 'Join codes must contain between 8 and 64 characters.' using errcode = '22023';
  end if;
  v_hash := extensions.crypt(v_code, extensions.gen_salt('bf', 12));

  if p_disable_existing then
    update public.organization_join_codes
    set is_active = false, rotated_at = pg_catalog.now()
    where organization_id = p_organization_id and is_active;
  end if;

  insert into public.organization_join_codes (
    organization_id, label, code_hash, approval_required, expires_at, max_uses, created_by
  ) values (
    p_organization_id, coalesce(nullif(btrim(p_label), ''), 'Organization join code'),
    v_hash, p_approval_required, p_expires_at, p_max_uses, auth.uid()
  ) returning id into v_join_code_id;

  perform private.write_audit(
    p_organization_id, 'join_code.rotated', 'organization_join_code', v_join_code_id::text,
    pg_catalog.jsonb_build_object(
      'expires_at', p_expires_at,
      'max_uses', p_max_uses,
      'approval_required', p_approval_required
    )
  );
  return query select v_join_code_id, v_code;
end;
$$;

create or replace function public.request_membership_with_code(
  p_organization_id uuid,
  p_raw_code text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_join_code public.organization_join_codes%rowtype;
  v_membership_id uuid;
  v_target_status public.membership_status;
  v_final_status public.membership_status;
  v_existing_status public.membership_status;
  v_existing_join_code_id uuid;
  v_consume_use boolean;
begin
  if v_user_id is null then
    raise exception 'Sign in before requesting membership.' using errcode = '42501';
  end if;
  select c.* into v_join_code
  from public.organization_join_codes c
  where c.organization_id = p_organization_id
    and c.code_hash = extensions.crypt(upper(btrim(p_raw_code)), c.code_hash)
    and c.is_active
  for update;

  if not found
     or not v_join_code.is_active
     or (v_join_code.expires_at is not null and v_join_code.expires_at <= pg_catalog.now()) then
    raise exception 'This join code is invalid, expired, disabled, or has reached its use limit.' using errcode = '22023';
  end if;

  -- The code row is already locked. Lock any existing membership as well so
  -- concurrent retries by the same account cannot consume the code twice.
  select m.id, m.status into v_membership_id, v_existing_status
  from public.organization_memberships m
  where m.organization_id = p_organization_id
    and m.user_id = v_user_id
  for update;
  v_consume_use := true;

  if found then
    select mr.join_code_id into v_existing_join_code_id
    from public.membership_requests mr
    where mr.membership_id = v_membership_id;

    -- An exact retry is a read of the already-created result, not another use,
    -- notification, or audit event. This remains valid at the max-use boundary.
    if v_existing_join_code_id = v_join_code.id
       and v_existing_status in ('pending', 'approved') then
      return v_membership_id;
    end if;

    -- Administrative rejection is terminal for this code. A person may apply
    -- again only with a genuinely new code issued by the organization.
    if v_existing_join_code_id = v_join_code.id
       and v_existing_status = 'rejected' then
      raise exception 'This membership request was rejected. Ask an organization administrator for a new join code before applying again.' using errcode = '42501';
    end if;
  end if;

  if v_join_code.max_uses is not null
     and v_join_code.use_count >= v_join_code.max_uses then
    raise exception 'This join code is invalid, expired, disabled, or has reached its use limit.' using errcode = '22023';
  end if;

  v_target_status := case
    when v_join_code.approval_required then 'pending'::public.membership_status
    else 'approved'::public.membership_status
  end;

  insert into public.organization_memberships (
    organization_id, user_id, role, status, joined_via, approved_by, approved_at
  ) values (
    p_organization_id, v_user_id, 'member', v_target_status, 'join_code',
    case when v_target_status = 'approved' then v_join_code.created_by else null end,
    case when v_target_status = 'approved' then pg_catalog.now() else null end
  )
  on conflict (organization_id, user_id) do update set
    status = case
      when public.organization_memberships.status = 'approved' then 'approved'::public.membership_status
      else v_target_status
    end,
    joined_via = 'join_code',
    approved_by = case
      when public.organization_memberships.status = 'approved' then public.organization_memberships.approved_by
      when v_target_status = 'approved' then v_join_code.created_by
      else null
    end,
    approved_at = case
      when public.organization_memberships.status = 'approved' then public.organization_memberships.approved_at
      when v_target_status = 'approved' then pg_catalog.now()
      else null
    end
  returning id, status into v_membership_id, v_final_status;

  if v_consume_use then
    update public.organization_join_codes
    set use_count = use_count + 1
    where id = v_join_code.id;
  end if;

  insert into public.membership_requests (
    organization_id, membership_id, user_id, join_code_id
  ) values (
    p_organization_id, v_membership_id, v_user_id, v_join_code.id
  )
  on conflict (membership_id) do update set
    invitation_id = null,
    join_code_id = excluded.join_code_id,
    reviewed_by = case when v_final_status = 'approved' then v_join_code.created_by else null end,
    reviewed_at = case when v_final_status = 'approved' then pg_catalog.now() else null end,
    created_at = pg_catalog.now();

  update public.membership_requests
  set reviewed_by = case when v_final_status = 'approved' then v_join_code.created_by else null end,
      reviewed_at = case when v_final_status = 'approved' then pg_catalog.now() else null end
  where membership_id = v_membership_id;

  insert into private.notification_outbox (organization_id, event_type, payload)
  values (
    p_organization_id,
    'membership.requested',
    pg_catalog.jsonb_build_object(
      'membership_id', v_membership_id,
      'method', 'join_code',
      'status', v_final_status,
      'approval_required', v_join_code.approval_required
    )
  );

  perform private.write_audit(
    p_organization_id,
    case when v_final_status = 'approved' then 'membership.auto_approved' else 'membership.requested' end,
    'organization_membership',
    v_membership_id::text,
    pg_catalog.jsonb_build_object('method', 'join_code', 'join_code_id', v_join_code.id)
  );

  return v_membership_id;
end;
$$;

create or replace function public.set_current_join_code_active(
  p_organization_id uuid,
  p_is_active boolean
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_join_code public.organization_join_codes%rowtype;
begin
  if not public.has_org_role(
    p_organization_id,
    array['owner', 'admin']::public.organization_role[]
  ) then
    raise exception 'Only organization administrators can enable or disable join codes.' using errcode = '42501';
  end if;

  -- Serialize toggles with rotation and always target the newest configured code.
  perform 1 from public.organizations o where o.id = p_organization_id for update;
  select c.* into v_join_code
  from public.organization_join_codes c
  where c.organization_id = p_organization_id
  order by c.created_at desc, c.id desc
  limit 1
  for update;

  if not found then
    raise exception 'This organization does not have a join code to toggle.' using errcode = 'P0002';
  end if;
  if p_is_active and (
    (v_join_code.expires_at is not null and v_join_code.expires_at <= pg_catalog.now())
    or (v_join_code.max_uses is not null and v_join_code.use_count >= v_join_code.max_uses)
  ) then
    raise exception 'An expired or exhausted join code cannot be enabled; rotate it instead.' using errcode = '22023';
  end if;

  if p_is_active then
    update public.organization_join_codes
    set is_active = false
    where organization_id = p_organization_id
      and id <> v_join_code.id
      and is_active;
  end if;
  update public.organization_join_codes
  set is_active = p_is_active
  where id = v_join_code.id;

  perform private.write_audit(
    p_organization_id,
    case when p_is_active then 'join_code.enabled' else 'join_code.disabled' end,
    'organization_join_code',
    v_join_code.id::text,
    pg_catalog.jsonb_build_object('is_active', p_is_active)
  );
  return v_join_code.id;
end;
$$;

create or replace function public.review_membership_request(
  p_membership_id uuid,
  p_status public.membership_status,
  p_role public.organization_role default 'member'
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_organization_id uuid;
begin
  if p_status not in ('approved', 'rejected') then
    raise exception 'A review must approve or reject the request.' using errcode = '22023';
  end if;

  select m.organization_id into v_organization_id
  from public.organization_memberships m
  where m.id = p_membership_id
  for update;

  if v_organization_id is null or not public.has_org_role(
    v_organization_id,
    array['owner', 'admin']::public.organization_role[]
  ) then
    raise exception 'Only organization administrators can review membership requests.' using errcode = '42501';
  end if;
  if p_role = 'owner' and not public.has_org_role(
    v_organization_id,
    array['owner']::public.organization_role[]
  ) then
    raise exception 'Only an owner can approve another owner.' using errcode = '42501';
  end if;

  update public.organization_memberships
  set role = p_role,
      status = p_status,
      approved_by = case when p_status = 'approved' then auth.uid() else null end,
      approved_at = case when p_status = 'approved' then pg_catalog.now() else null end
  where id = p_membership_id;

  update public.membership_requests
  set reviewed_by = auth.uid(), reviewed_at = pg_catalog.now()
  where membership_id = p_membership_id;

  insert into private.notification_outbox (organization_id, event_type, payload)
  values (
    v_organization_id,
    'membership.reviewed',
    pg_catalog.jsonb_build_object('membership_id', p_membership_id, 'status', p_status, 'role', p_role)
  );

  perform private.write_audit(
    v_organization_id, 'membership.reviewed', 'organization_membership', p_membership_id::text,
    pg_catalog.jsonb_build_object('status', p_status, 'role', p_role)
  );
end;
$$;

-- Survey lifecycle operations act on the stable survey identity. Every current
-- version card therefore archives, deletes, or restores atomically.
create or replace function public.archive_survey(p_survey_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_survey public.surveys%rowtype;
begin
  select s.* into v_survey from public.surveys s where s.id = p_survey_id for update;
  if not found then
    raise exception 'Survey not found.' using errcode = 'P0002';
  end if;
  if not public.has_org_role(
    v_survey.organization_id,
    array['owner', 'admin', 'survey_manager']::public.organization_role[]
  ) then
    raise exception 'You do not have permission to archive this survey.' using errcode = '42501';
  end if;
  if v_survey.deleted_at is not null then
    raise exception 'Restore this survey from Recently Deleted before archiving it.' using errcode = '55000';
  end if;
  if v_survey.current_published_version_id is not null then
    -- Serialize the close boundary with submit_survey_response. A submission
    -- already holding this version lock finishes first; every later submission
    -- observes the archived identity and is rejected.
    perform pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended(v_survey.current_published_version_id::text, 0)
    );
  end if;

  update public.surveys
  set status = 'archived', archived_at = coalesce(archived_at, pg_catalog.now())
  where id = v_survey.id;
  perform private.write_audit(
    v_survey.organization_id, 'survey.archived', 'survey', v_survey.id::text,
    pg_catalog.jsonb_build_object('previous_status', v_survey.status)
  );
  return v_survey.id;
end;
$$;

create or replace function public.delete_survey(p_survey_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_survey public.surveys%rowtype;
  v_deleted_at timestamptz := pg_catalog.now();
begin
  select s.* into v_survey from public.surveys s where s.id = p_survey_id for update;
  if not found then
    raise exception 'Survey not found.' using errcode = 'P0002';
  end if;
  if not public.has_org_role(
    v_survey.organization_id,
    array['owner', 'admin', 'survey_manager']::public.organization_role[]
  ) then
    raise exception 'You do not have permission to delete this survey.' using errcode = '42501';
  end if;
  -- Retrying the operation must not extend the 30-day recovery window.
  if v_survey.deleted_at is not null then
    return v_survey.id;
  end if;
  if v_survey.current_published_version_id is not null then
    perform pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended(v_survey.current_published_version_id::text, 0)
    );
  end if;

  update public.surveys
  set status_before_deletion = v_survey.status,
      status = 'archived',
      archived_at = coalesce(archived_at, v_deleted_at),
      deleted_at = v_deleted_at,
      deletion_due_at = v_deleted_at + interval '30 days'
  where id = v_survey.id;
  perform private.write_audit(
    v_survey.organization_id, 'survey.moved_to_recently_deleted', 'survey', v_survey.id::text,
    pg_catalog.jsonb_build_object(
      'previous_status', v_survey.status,
      'deletion_due_at', v_deleted_at + interval '30 days'
    )
  );
  return v_survey.id;
end;
$$;

create or replace function public.restore_deleted_survey(p_survey_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_survey public.surveys%rowtype;
  v_restored_status public.survey_status;
begin
  select s.* into v_survey from public.surveys s where s.id = p_survey_id for update;
  if not found then
    raise exception 'Survey not found.' using errcode = 'P0002';
  end if;
  if not public.has_org_role(
    v_survey.organization_id,
    array['owner', 'admin', 'survey_manager']::public.organization_role[]
  ) then
    raise exception 'You do not have permission to restore this survey.' using errcode = '42501';
  end if;
  if v_survey.deleted_at is null then
    raise exception 'This survey is not in Recently Deleted.' using errcode = '55000';
  end if;
  v_restored_status := coalesce(v_survey.status_before_deletion, 'archived'::public.survey_status);

  update public.surveys
  set status = v_restored_status,
      archived_at = case when v_restored_status = 'archived' then archived_at else null end,
      deleted_at = null,
      deletion_due_at = null,
      status_before_deletion = null
  where id = v_survey.id;
  perform private.write_audit(
    v_survey.organization_id, 'survey.restored', 'survey', v_survey.id::text,
    pg_catalog.jsonb_build_object('restored_status', v_restored_status)
  );
  return v_survey.id;
end;
$$;

-- Owners and administrators can use these rows with the authenticated Storage
-- API. The subsequent hard-delete RPC refuses to remove database history until
-- each tracked object is absent from storage.objects.
create or replace function public.get_survey_deletion_uploads(p_survey_id uuid)
returns table (bucket_id text, object_path text)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_survey public.surveys%rowtype;
begin
  select s.* into v_survey from public.surveys s where s.id = p_survey_id;
  if not found or v_survey.deleted_at is null then
    raise exception 'A survey must be in Recently Deleted before its uploads can be removed.' using errcode = '55000';
  end if;
  if not public.has_org_role(
    v_survey.organization_id,
    array['owner', 'admin']::public.organization_role[]
  ) then
    raise exception 'Only an organization owner or administrator can permanently delete survey data.' using errcode = '42501';
  end if;

  return query
  select u.bucket_id, u.object_path
  from private.response_upload_objects u
  where u.survey_version_id in (
    select sv.id from public.survey_versions sv where sv.survey_id = v_survey.id
  )
  order by u.created_at, u.id;
end;
$$;

create or replace function public.permanently_delete_survey(p_survey_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_survey public.surveys%rowtype;
begin
  select s.* into v_survey from public.surveys s where s.id = p_survey_id for update;
  if not found then
    raise exception 'Survey not found.' using errcode = 'P0002';
  end if;
  if not public.has_org_role(
    v_survey.organization_id,
    array['owner', 'admin']::public.organization_role[]
  ) then
    raise exception 'Only an organization owner or administrator can permanently delete survey data.' using errcode = '42501';
  end if;
  if v_survey.deleted_at is null then
    raise exception 'Move this survey to Recently Deleted before permanently deleting it.' using errcode = '55000';
  end if;
  if exists (
    select 1
    from private.response_upload_objects u
    join storage.objects o on o.bucket_id = u.bucket_id and o.name = u.object_path
    where u.survey_version_id in (
      select sv.id from public.survey_versions sv where sv.survey_id = v_survey.id
    )
  ) then
    raise exception 'Delete every attached response upload through the Storage API before deleting the survey record.'
      using errcode = '55000';
  end if;

  perform private.write_audit(
    v_survey.organization_id, 'survey.permanently_deleted', 'survey', v_survey.id::text,
    pg_catalog.jsonb_build_object('deleted_at', v_survey.deleted_at, 'manual', true)
  );
  delete from public.surveys s where s.id = v_survey.id;
  return v_survey.id;
end;
$$;

-- A trusted scheduled worker calls list_due_survey_deletions(), removes the
-- returned Storage objects with the service-role Storage API, then calls this
-- function. Browser clients are intentionally never granted either function.
create or replace function public.list_due_survey_deletions(p_limit integer default 100)
returns table (
  survey_id uuid,
  deletion_due_at timestamptz,
  upload_objects jsonb
)
language sql
stable
security definer
set search_path = ''
as $$
  select
    s.id,
    s.deletion_due_at,
    coalesce((
      select pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object('bucket_id', u.bucket_id, 'object_path', u.object_path)
        order by u.created_at, u.id
      )
      from private.response_upload_objects u
      join storage.objects o on o.bucket_id = u.bucket_id and o.name = u.object_path
      where u.survey_version_id in (
        select sv.id from public.survey_versions sv where sv.survey_id = s.id
      )
    ), '[]'::pg_catalog.jsonb)
  from public.surveys s
  where s.deleted_at is not null
    and s.deletion_due_at <= pg_catalog.now()
  order by s.deletion_due_at, s.id
  limit greatest(1, least(coalesce(p_limit, 100), 500));
$$;

create or replace function public.purge_due_deleted_surveys(p_limit integer default 100)
returns table (deleted_survey_id uuid)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_survey public.surveys%rowtype;
begin
  for v_survey in
    select s.*
    from public.surveys s
    where s.deleted_at is not null
      and s.deletion_due_at <= pg_catalog.now()
    order by s.deletion_due_at, s.id
    for update skip locked
    limit greatest(1, least(coalesce(p_limit, 100), 500))
  loop
    -- Fail closed: a worker must successfully remove all physical Storage
    -- objects before this database transaction erases their tracking rows.
    if exists (
      select 1
      from private.response_upload_objects u
      join storage.objects o on o.bucket_id = u.bucket_id and o.name = u.object_path
      where u.survey_version_id in (
        select sv.id from public.survey_versions sv where sv.survey_id = v_survey.id
      )
    ) then
      continue;
    end if;

    perform private.write_audit(
      v_survey.organization_id, 'survey.permanently_deleted', 'survey', v_survey.id::text,
      pg_catalog.jsonb_build_object('deleted_at', v_survey.deleted_at, 'automatic', true)
    );
    delete from public.surveys s where s.id = v_survey.id;
    deleted_survey_id := v_survey.id;
    return next;
  end loop;
end;
$$;

create or replace function public.publish_survey_version(p_survey_version_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_version public.survey_versions%rowtype;
  v_survey public.surveys%rowtype;
begin
  select sv.* into v_version
  from public.survey_versions sv
  where sv.id = p_survey_version_id
  for update;
  if not found then
    raise exception 'Survey version not found.' using errcode = 'P0002';
  end if;

  select s.* into v_survey from public.surveys s where s.id = v_version.survey_id for update;
  if not public.has_org_role(
    v_survey.organization_id,
    array['owner', 'admin', 'survey_manager']::public.organization_role[]
  ) then
    raise exception 'You do not have permission to publish this survey.' using errcode = '42501';
  end if;
  if v_survey.deleted_at is not null or v_survey.status = 'archived' then
    raise exception 'Restore this survey before publishing a draft version.' using errcode = '55000';
  end if;
  if v_version.status <> 'draft' then
    raise exception 'Only a draft can be published. Published versions must be edited as a copy.' using errcode = '55000';
  end if;
  if not exists (
    select 1 from public.survey_questions q where q.survey_version_id = v_version.id
  ) then
    raise exception 'Add at least one question before publishing.' using errcode = '23514';
  end if;
  if exists (
    select 1
    from public.survey_logic_rules lr
    join public.survey_questions source_question on source_question.id = lr.source_question_id
    join public.survey_questions target_question on target_question.id = lr.target_question_id
    where lr.survey_version_id = v_version.id
      and source_question.position >= target_question.position
  ) then
    raise exception 'Conditional logic must point forward from an earlier question to a later question.'
      using errcode = '23514';
  end if;
  if exists (
    select 1
    from public.survey_logic_rules lr
    join public.survey_questions target_question on target_question.id = lr.target_question_id
    where lr.survey_version_id = v_version.id
      and lr.action = 'require'
      and target_question.type = 'information'
  ) then
    raise exception 'An information block cannot be conditionally required because it does not accept an answer.'
      using errcode = '23514';
  end if;
  if exists (
    select 1
    from public.survey_questions q
    join public.map_versions mv on mv.id = q.map_version_id
    where q.survey_version_id = v_version.id
      and q.type = 'map_tiles'
      and (
        (
          mv.source_kind = 'static'
          and (
            mv.region_mode = 'none'
            or not exists (select 1 from public.map_regions mr where mr.map_version_id = mv.id)
          )
        )
        or (
          mv.source_kind = 'mapbox'
          and (
            nullif(btrim(mv.mapbox_tileset_url), '') is null
            or nullif(btrim(mv.mapbox_source_layer), '') is null
            or nullif(btrim(mv.processing_metadata ->> 'featureIdProperty'), '') is null
          )
        )
      )
  ) then
    raise exception 'Static tile-selection maps require stored regions; Mapbox tile-selection maps require a tileset, source layer, and featureIdProperty.'
      using errcode = '23514';
  end if;
  if exists (
    select 1
    from public.survey_questions q
    join public.map_versions mv on mv.id = q.map_version_id
    where q.survey_version_id = v_version.id
      and mv.source_kind = 'mapbox'
  ) and not exists (
    select 1 from public.organization_integrations i
    where i.organization_id = v_survey.organization_id
      and i.provider = 'mapbox'
      and i.status = 'connected'
  ) then
    raise exception 'Connect Mapbox before publishing questions that use Mapbox maps.' using errcode = '23514';
  end if;
  if exists (
    select 1
    from public.survey_questions q
    join public.map_versions mv on mv.id = q.map_version_id
    where q.survey_version_id = v_version.id
      and mv.source_kind = 'static'
      and (
        mv.static_bucket <> 'survey-static-maps'
        or public.storage_path_first_uuid(mv.static_object_path) is distinct from v_survey.organization_id
        or not exists (
          select 1 from storage.objects stored_object
          where stored_object.bucket_id = mv.static_bucket
            and stored_object.name = mv.static_object_path
        )
      )
  ) then
    raise exception 'Every static map question must reference an uploaded object in the organization’s private static-map bucket.'
      using errcode = '23514';
  end if;
  if exists (
    select 1 from public.survey_logic_rules lr
    where lr.survey_version_id = v_version.id
      and lr.operator in (
        'drawing_overlaps_region', 'drawing_touches_region', 'drawing_inside_region',
        'drawing_contains_region', 'drawing_avoids_region'
      )
  ) then
    raise exception 'Drawing-location logic requires a trusted server-side geometry validator. Use answered/not answered or tile-selection named-area logic.'
      using errcode = '23514';
  end if;
  if exists (
    select 1
    from public.survey_questions q
    where q.survey_version_id = v_version.id
      and q.type = 'image_choice'
      and (
        not exists (select 1 from public.survey_question_options o where o.question_id = q.id)
        or exists (
          select 1 from public.survey_question_options o
          where o.question_id = q.id and o.image_url is null
        )
      )
  ) then
    raise exception 'Every image-choice option must include a safe browser-deliverable image_url.'
      using errcode = '23514';
  end if;
  if exists (
    with recursive logic_walk (source_question_id, current_question_id, path, has_cycle) as (
      select
        lr.source_question_id,
        lr.target_question_id,
        array[lr.source_question_id, lr.target_question_id]::uuid[],
        lr.target_question_id = lr.source_question_id
      from public.survey_logic_rules lr
      where lr.survey_version_id = v_version.id
      union all
      select
        lw.source_question_id,
        next_rule.target_question_id,
        lw.path || next_rule.target_question_id,
        next_rule.target_question_id = any(lw.path)
      from logic_walk lw
      join public.survey_logic_rules next_rule
        on next_rule.survey_version_id = v_version.id
       and next_rule.source_question_id = lw.current_question_id
      where not lw.has_cycle
    )
    select 1 from logic_walk where has_cycle
  ) then
    raise exception 'Conditional logic contains a cycle. Remove the loop before publishing.' using errcode = '23514';
  end if;

  -- Lock exact map versions before making the survey visible. There is no
  -- automatic static fallback for Mapbox-backed questions.
  update public.map_versions mv
  set locked_at = pg_catalog.now()
  where mv.id in (
    select distinct q.map_version_id
    from public.survey_questions q
    where q.survey_version_id = v_version.id and q.map_version_id is not null
  ) and mv.locked_at is null;

  update public.survey_versions
  set status = 'published', published_at = pg_catalog.now()
  where id = v_version.id;

  update public.surveys
  set current_published_version_id = v_version.id,
      current_draft_version_id = null,
      status = 'published'
  where id = v_survey.id;

  perform private.write_audit(
    v_survey.organization_id, 'survey.published', 'survey_version', v_version.id::text,
    pg_catalog.jsonb_build_object('survey_id', v_survey.id, 'version_number', v_version.version_number)
  );
  return v_version.id;
end;
$$;

create or replace function public.copy_published_survey_version(p_survey_version_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_source public.survey_versions%rowtype;
  v_survey public.surveys%rowtype;
  v_new_version_id uuid;
  v_new_version_number integer;
  v_question_map jsonb := '{}'::jsonb;
  v_area_map jsonb := '{}'::jsonb;
  v_question record;
  v_area record;
  v_rule record;
  v_new_question_id uuid;
  v_new_area_id uuid;
begin
  select sv.* into v_source
  from public.survey_versions sv
  where sv.id = p_survey_version_id;
  if not found or v_source.status <> 'published' then
    raise exception 'Only a published survey version can be edited as a copy.' using errcode = '22023';
  end if;

  select s.* into v_survey from public.surveys s where s.id = v_source.survey_id for update;
  if not public.has_org_role(
    v_survey.organization_id,
    array['owner', 'admin', 'survey_manager']::public.organization_role[]
  ) then
    raise exception 'You do not have permission to copy this survey.' using errcode = '42501';
  end if;
  if v_survey.deleted_at is not null or v_survey.status = 'archived' then
    raise exception 'Restore this survey before creating an editable copy.' using errcode = '55000';
  end if;
  if v_survey.current_draft_version_id is not null then
    raise exception 'This survey already has an editable draft.' using errcode = '55000';
  end if;

  select coalesce(max(sv.version_number), 0) + 1 into v_new_version_number
  from public.survey_versions sv where sv.survey_id = v_survey.id;

  insert into public.survey_versions (
    survey_id, version_number, status, parent_version_id, title, purpose, access,
    privacy, pseudonymous_linking_enabled, duplicate_policy, allow_save_and_resume,
    opens_at, closes_at, response_limit, retention_days, completion_message,
    appearance, notification_config, created_by
  ) values (
    v_survey.id, v_new_version_number, 'draft', v_source.id, v_source.title,
    v_source.purpose, v_source.access, v_source.privacy,
    v_source.pseudonymous_linking_enabled, v_source.duplicate_policy,
    v_source.allow_save_and_resume, v_source.opens_at, v_source.closes_at,
    v_source.response_limit, v_source.retention_days, v_source.completion_message,
    v_source.appearance, v_source.notification_config, auth.uid()
  ) returning id into v_new_version_id;

  insert into public.survey_version_setting_values (survey_version_id, setting_key, value)
  select v_new_version_id, svs.setting_key, svs.value
  from public.survey_version_setting_values svs
  where svs.survey_version_id = v_source.id;

  for v_question in
    select q.* from public.survey_questions q
    where q.survey_version_id = v_source.id order by q.position
  loop
    v_new_question_id := gen_random_uuid();
    insert into public.survey_questions (
      id, survey_version_id, question_key, position, type, title, description,
      required, map_version_id, settings
    ) values (
      v_new_question_id, v_new_version_id, v_question.question_key,
      v_question.position, v_question.type, v_question.title, v_question.description,
      v_question.required, v_question.map_version_id, v_question.settings
    );
    v_question_map := v_question_map || pg_catalog.jsonb_build_object(
      v_question.id::text, v_new_question_id::text
    );

    insert into public.survey_question_options (
      question_id, option_key, position, label, value, image_url, image_storage_path
    )
    select v_new_question_id, o.option_key, o.position, o.label, o.value, o.image_url, o.image_storage_path
    from public.survey_question_options o
    where o.question_id = v_question.id;
  end loop;

  for v_area in
    select a.* from public.survey_map_trigger_areas a
    where a.survey_version_id = v_source.id order by a.created_at, a.id
  loop
    v_new_area_id := gen_random_uuid();
    insert into public.survey_map_trigger_areas (
      id, survey_version_id, map_version_id, area_key, label, geometry
    ) values (
      v_new_area_id, v_new_version_id, v_area.map_version_id,
      v_area.area_key, v_area.label, v_area.geometry
    );
    v_area_map := v_area_map || pg_catalog.jsonb_build_object(v_area.id::text, v_new_area_id::text);
  end loop;

  for v_rule in
    select lr.* from public.survey_logic_rules lr
    where lr.survey_version_id = v_source.id order by lr.position
  loop
    insert into public.survey_logic_rules (
      survey_version_id, position, source_question_id, target_question_id,
      operator, action, comparison_value, trigger_area_id, overlap_threshold
    ) values (
      v_new_version_id,
      v_rule.position,
      (v_question_map ->> v_rule.source_question_id::text)::uuid,
      (v_question_map ->> v_rule.target_question_id::text)::uuid,
      v_rule.operator,
      v_rule.action,
      v_rule.comparison_value,
      case when v_rule.trigger_area_id is null then null
           else (v_area_map ->> v_rule.trigger_area_id::text)::uuid end,
      v_rule.overlap_threshold
    );
  end loop;

  update public.surveys set current_draft_version_id = v_new_version_id where id = v_survey.id;
  perform private.write_audit(
    v_survey.organization_id, 'survey.editable_copy_created', 'survey_version', v_new_version_id::text,
    pg_catalog.jsonb_build_object('copied_from_version_id', v_source.id)
  );
  return v_new_version_id;
end;
$$;

create or replace function private.answer_is_present(p_answer jsonb)
returns boolean
language sql
immutable
security definer
set search_path = ''
as $$
  select case pg_catalog.jsonb_typeof(p_answer)
    when 'null' then false
    when 'string' then char_length(btrim(p_answer #>> '{}')) > 0
    when 'array' then pg_catalog.jsonb_array_length(p_answer) > 0
    when 'object' then
      case
        -- Map controls retain mapId/mapVersion after the respondent clears the
        -- visible selection. Treat that metadata-only shell as unanswered so
        -- required and conditional rules match the browser. Non-map structured
        -- answers (uploads and matrices) keep the ordinary non-empty behavior.
        when p_answer ? 'mapId'
          or p_answer ? 'mapVersion'
          or pg_catalog.jsonb_typeof(p_answer -> 'selectedRegionIds') = 'array'
          or pg_catalog.jsonb_typeof(p_answer -> 'rawStroke') = 'array'
          or pg_catalog.jsonb_typeof(p_answer -> 'derivedPolygon') = 'array'
        then
          (case when pg_catalog.jsonb_typeof(p_answer -> 'selectedRegionIds') = 'array'
            then pg_catalog.jsonb_array_length(p_answer -> 'selectedRegionIds') > 0 else false end)
          or (case when pg_catalog.jsonb_typeof(p_answer -> 'rawStroke') = 'array'
            then pg_catalog.jsonb_array_length(p_answer -> 'rawStroke') > 0 else false end)
          or (case when pg_catalog.jsonb_typeof(p_answer -> 'derivedPolygon') = 'array'
            then pg_catalog.jsonb_array_length(p_answer -> 'derivedPolygon') > 0 else false end)
        else p_answer <> '{}'::jsonb
      end
    else p_answer is not null
  end;
$$;

-- Returns NULL when a rule needs geometric computation that this migration
-- intentionally does not approximate. The required-answer validator treats an
-- unknown show-rule result as visible, which fails closed rather than silently
-- excusing a required answer.
create or replace function private.logic_rule_matches(
  p_operator public.logic_operator,
  p_comparison jsonb,
  p_answer jsonb
)
returns boolean
language plpgsql
immutable
security definer
set search_path = ''
as $$
declare
  v_answer_text text;
  v_comparison_text text;
  v_selected jsonb;
begin
  if p_operator = 'not_answered' then
    return not private.answer_is_present(p_answer);
  elsif p_operator = 'answered' then
    return private.answer_is_present(p_answer);
  elsif p_operator in ('selected_region_count_at_least', 'selected_region_count_at_most') then
    if pg_catalog.jsonb_typeof(p_comparison) <> 'number' then
      return false;
    end if;
    -- An unanswered tile question has zero selected regions. This mirrors the
    -- browser evaluator, including the useful "at most 0" condition.
    if p_answer is null or p_answer = 'null'::jsonb then
      v_selected := '[]'::jsonb;
    elsif pg_catalog.jsonb_typeof(p_answer) = 'object'
          and (p_answer -> 'selectedRegionIds') is null then
      v_selected := '[]'::jsonb;
    elsif pg_catalog.jsonb_typeof(p_answer) = 'object'
          and pg_catalog.jsonb_typeof(p_answer -> 'selectedRegionIds') = 'array' then
      v_selected := p_answer -> 'selectedRegionIds';
    else
      return false;
    end if;
    if p_operator = 'selected_region_count_at_least' then
      return pg_catalog.jsonb_array_length(v_selected) >= (p_comparison::text)::integer;
    end if;
    return pg_catalog.jsonb_array_length(v_selected) <= (p_comparison::text)::integer;
  elsif not private.answer_is_present(p_answer) then
    return false;
  end if;

  if p_operator = 'equals' then
    return p_answer = p_comparison;
  elsif p_operator = 'not_equals' then
    return p_answer <> p_comparison;
  elsif p_operator = 'contains' then
    if pg_catalog.jsonb_typeof(p_answer) = 'array' then
      return p_answer @> pg_catalog.jsonb_build_array(p_comparison);
    elsif pg_catalog.jsonb_typeof(p_answer) = 'string'
          and pg_catalog.jsonb_typeof(p_comparison) = 'string' then
      v_answer_text := p_answer #>> '{}';
      v_comparison_text := p_comparison #>> '{}';
      return pg_catalog.strpos(lower(v_answer_text), lower(v_comparison_text)) > 0;
    end if;
    return false;
  elsif p_operator in ('greater_than', 'less_than') then
    if pg_catalog.jsonb_typeof(p_answer) <> 'number'
       or pg_catalog.jsonb_typeof(p_comparison) <> 'number' then
      return false;
    end if;
    if p_operator = 'greater_than' then
      return (p_answer::text)::numeric > (p_comparison::text)::numeric;
    end if;
    return (p_answer::text)::numeric < (p_comparison::text)::numeric;
  elsif p_operator = 'selected_region' then
    if pg_catalog.jsonb_typeof(p_answer) <> 'object' then
      return false;
    end if;
    v_selected := p_answer -> 'selectedRegionIds';
    if pg_catalog.jsonb_typeof(v_selected) <> 'array' then
      return false;
    end if;
    v_comparison_text := p_comparison #>> '{}';
    return exists (
      select 1 from pg_catalog.jsonb_array_elements_text(v_selected) selected(value)
      where selected.value = v_comparison_text
    );
  elsif p_operator in (
    'drawing_overlaps_region', 'drawing_touches_region', 'drawing_inside_region',
    'drawing_contains_region', 'drawing_avoids_region'
  ) then
    return null;
  end if;
  return null;
end;
$$;

create or replace function private.validate_normalized_points(
  p_points jsonb,
  p_label text,
  p_minimum_points integer
)
returns void
language plpgsql
immutable
security definer
set search_path = ''
as $$
declare
  v_point jsonb;
  v_count integer;
begin
  if pg_catalog.jsonb_typeof(p_points) <> 'array' then
    raise exception '% must be an array of points.', p_label using errcode = '22023';
  end if;
  v_count := pg_catalog.jsonb_array_length(p_points);
  if v_count < p_minimum_points or v_count > 10000 then
    raise exception '% must contain between % and 10000 points.', p_label, p_minimum_points
      using errcode = '22023';
  end if;
  for v_point in select value from pg_catalog.jsonb_array_elements(p_points)
  loop
    if pg_catalog.jsonb_typeof(v_point) <> 'object'
       or pg_catalog.jsonb_typeof(v_point -> 'x') <> 'number'
       or pg_catalog.jsonb_typeof(v_point -> 'y') <> 'number'
       or ((v_point ->> 'x')::numeric) < 0
       or ((v_point ->> 'x')::numeric) > 1
       or ((v_point ->> 'y')::numeric) < 0
       or ((v_point ->> 'y')::numeric) > 1 then
      raise exception '% contains a malformed point; x and y must be numbers from 0 through 1.', p_label
        using errcode = '22023';
    end if;
  end loop;
end;
$$;

create or replace function private.validate_survey_answers(
  p_survey_version_id uuid,
  p_answers jsonb,
  p_user_id uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_question record;
  v_rule record;
  v_answer jsonb;
  v_value jsonb;
  v_visible boolean;
  v_rule_result boolean;
  v_unknown_rule boolean;
  v_has_show_rules boolean;
  v_any_show_rule boolean;
  v_conditionally_required boolean;
  v_effectively_required boolean;
  v_text text;
  v_number numeric;
  v_min numeric;
  v_max numeric;
  v_map_version_number integer;
  v_map_asset_id uuid;
  v_map_source_kind public.map_source_kind;
  v_selected jsonb;
  v_privacy public.privacy_mode;
  v_file_path text;
  v_file_bucket text;
  v_file_size bigint;
  v_option_count integer;
begin
  select sv.privacy into v_privacy
  from public.survey_versions sv where sv.id = p_survey_version_id;

  for v_question in
    select q.* from public.survey_questions q
    where q.survey_version_id = p_survey_version_id
    order by q.position
  loop
    v_answer := p_answers -> v_question.id::text;
    v_visible := true;
    v_unknown_rule := false;
    v_has_show_rules := false;
    v_any_show_rule := false;
    v_conditionally_required := false;

    for v_rule in
      select lr.* from public.survey_logic_rules lr
      where lr.survey_version_id = p_survey_version_id
        and lr.target_question_id = v_question.id
        and lr.action = 'show'
      order by lr.position
    loop
      v_has_show_rules := true;
      v_rule_result := private.logic_rule_matches(
        v_rule.operator,
        v_rule.comparison_value,
        p_answers -> v_rule.source_question_id::text
      );
      if v_rule_result is true then
        v_any_show_rule := true;
      elsif v_rule_result is null then
        v_unknown_rule := true;
      end if;
    end loop;

    if v_has_show_rules then
      v_visible := v_any_show_rule or v_unknown_rule;
    end if;

    if v_visible then
      for v_rule in
        select lr.* from public.survey_logic_rules lr
        where lr.survey_version_id = p_survey_version_id
          and lr.target_question_id = v_question.id
          and lr.action = 'hide'
        order by lr.position
      loop
        v_rule_result := private.logic_rule_matches(
          v_rule.operator,
          v_rule.comparison_value,
          p_answers -> v_rule.source_question_id::text
        );
        if v_rule_result is true then
          v_visible := false;
          exit;
        end if;
      end loop;
    end if;

    if v_visible then
      for v_rule in
        select lr.* from public.survey_logic_rules lr
        where lr.survey_version_id = p_survey_version_id
          and lr.target_question_id = v_question.id
          and lr.action = 'require'
        order by lr.position
      loop
        v_rule_result := private.logic_rule_matches(
          v_rule.operator,
          v_rule.comparison_value,
          p_answers -> v_rule.source_question_id::text
        );
        if v_rule_result is true or v_rule_result is null then
          v_conditionally_required := true;
          exit;
        end if;
      end loop;
    end if;

    v_effectively_required := v_question.required or v_conditionally_required;

    -- Never retain answers that the published logic says were hidden. This
    -- prevents stale or modified clients from contaminating response exports.
    if not v_visible then
      if private.answer_is_present(v_answer) then
        raise exception 'Hidden question "%" (%) must not include an answer.',
          v_question.title, v_question.id using errcode = '22023';
      end if;
      continue;
    end if;

    if v_effectively_required and v_visible
       and not private.answer_is_present(v_answer) then
      raise exception 'Required question "%" (%) is missing an answer.',
        v_question.title, v_question.id using errcode = '22023';
    end if;

    if not private.answer_is_present(v_answer) then
      continue;
    end if;

    if v_question.type in ('short_text', 'long_text') then
      if pg_catalog.jsonb_typeof(v_answer) <> 'string' then
        raise exception 'Question % requires a text answer.', v_question.id using errcode = '22023';
      end if;
    elsif v_question.type = 'number' then
      if pg_catalog.jsonb_typeof(v_answer) <> 'number' then
        raise exception 'Question % requires a numeric answer.', v_question.id using errcode = '22023';
      end if;
      v_number := (v_answer::text)::numeric;
      v_min := case when v_question.settings ? 'min' then (v_question.settings ->> 'min')::numeric else null end;
      v_max := case when v_question.settings ? 'max' then (v_question.settings ->> 'max')::numeric else null end;
      if (v_min is not null and v_number < v_min) or (v_max is not null and v_number > v_max) then
        raise exception 'Question % is outside its permitted numeric range.', v_question.id using errcode = '22023';
      end if;
    elsif v_question.type = 'rating' then
      if pg_catalog.jsonb_typeof(v_answer) <> 'number' then
        raise exception 'Question % requires a numeric rating.', v_question.id using errcode = '22023';
      end if;
      v_number := (v_answer::text)::numeric;
      v_min := case when v_question.settings ? 'scaleMin' then (v_question.settings ->> 'scaleMin')::numeric else 1 end;
      v_max := case when v_question.settings ? 'scaleMax' then (v_question.settings ->> 'scaleMax')::numeric else 5 end;
      if v_number < v_min or v_number > v_max then
        raise exception 'Question % is outside its permitted rating scale.', v_question.id using errcode = '22023';
      end if;
    elsif v_question.type in ('yes_no', 'consent') then
      if pg_catalog.jsonb_typeof(v_answer) <> 'boolean' then
        raise exception 'Question % requires a true-or-false answer.', v_question.id using errcode = '22023';
      end if;
      if v_question.type = 'consent' and v_effectively_required and v_answer <> 'true'::jsonb then
        raise exception 'Required consent question % must be accepted.', v_question.id using errcode = '22023';
      end if;
    elsif v_question.type = 'date' then
      if pg_catalog.jsonb_typeof(v_answer) <> 'string'
         or (v_answer #>> '{}') !~ '^\d{4}-\d{2}-\d{2}$' then
        raise exception 'Question % requires a date in YYYY-MM-DD format.', v_question.id using errcode = '22023';
      end if;
      begin
        perform (v_answer #>> '{}')::date;
      exception when datetime_field_overflow then
        raise exception 'Question % contains an invalid calendar date.', v_question.id using errcode = '22023';
      end;
    elsif v_question.type = 'time' then
      if pg_catalog.jsonb_typeof(v_answer) <> 'string'
         or (v_answer #>> '{}') !~ '^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$' then
        raise exception 'Question % requires a 24-hour time value.', v_question.id using errcode = '22023';
      end if;
    elsif v_question.type in ('single_choice', 'dropdown', 'image_choice') then
      if pg_catalog.jsonb_typeof(v_answer) <> 'string' then
        raise exception 'Question % requires one option value.', v_question.id using errcode = '22023';
      end if;
      if not coalesce((v_question.settings ->> 'allowOther')::boolean, false)
         and not exists (
           select 1 from public.survey_question_options o
           where o.question_id = v_question.id and o.value = (v_answer #>> '{}')
         ) then
        raise exception 'Question % contains an option that is not in the published survey.', v_question.id
          using errcode = '22023';
      end if;
    elsif v_question.type in ('multiple_choice', 'ranking') then
      if pg_catalog.jsonb_typeof(v_answer) <> 'array'
         or exists (
           select 1 from pg_catalog.jsonb_array_elements(v_answer) item(value)
           where pg_catalog.jsonb_typeof(item.value) <> 'string'
         ) then
        raise exception 'Question % requires an array of option values.', v_question.id using errcode = '22023';
      end if;
      if (
        select count(*) from pg_catalog.jsonb_array_elements_text(v_answer)
      ) <> (
        select count(distinct item.value) from pg_catalog.jsonb_array_elements_text(v_answer) item(value)
      ) then
        raise exception 'Question % contains a duplicate option.', v_question.id using errcode = '22023';
      end if;
      if not coalesce((v_question.settings ->> 'allowOther')::boolean, false)
         and exists (
           select 1 from pg_catalog.jsonb_array_elements_text(v_answer) item(value)
           where not exists (
             select 1 from public.survey_question_options o
             where o.question_id = v_question.id and o.value = item.value
           )
         ) then
        raise exception 'Question % contains an option that is not in the published survey.', v_question.id
          using errcode = '22023';
      end if;
      if v_question.type = 'ranking' and (
        pg_catalog.jsonb_array_length(v_answer) <> (
          select count(*) from public.survey_question_options o where o.question_id = v_question.id
        )
        or exists (
          select 1 from public.survey_question_options o
          where o.question_id = v_question.id
            and not (v_answer @> pg_catalog.jsonb_build_array(o.value))
        )
      ) then
        raise exception 'Question % requires every ranking option exactly once.', v_question.id
          using errcode = '22023';
      end if;
    elsif v_question.type = 'matrix' then
      if pg_catalog.jsonb_typeof(v_answer) <> 'object'
         or pg_catalog.jsonb_typeof(v_question.settings -> 'matrixColumns') <> 'array'
         or pg_catalog.jsonb_array_length(v_question.settings -> 'matrixColumns') = 0
         or exists (
           select 1 from pg_catalog.jsonb_array_elements(v_question.settings -> 'matrixColumns') column_value(value)
           where pg_catalog.jsonb_typeof(column_value.value) <> 'string'
         ) then
        raise exception 'Question % requires a row-to-option object.', v_question.id using errcode = '22023';
      end if;
      select count(*) into v_option_count from public.survey_question_options o
      where o.question_id = v_question.id;
      if exists (
        select 1 from pg_catalog.jsonb_each(v_answer) cell(row_value, column_value)
        where not exists (
          select 1 from public.survey_question_options row_option
          where row_option.question_id = v_question.id and row_option.value = cell.row_value
        )
        or pg_catalog.jsonb_typeof(cell.column_value) <> 'string'
        or not exists (
          select 1
          from pg_catalog.jsonb_array_elements_text(v_question.settings -> 'matrixColumns') allowed(column_label)
          where allowed.column_label = cell.column_value #>> '{}'
        )
      ) then
        raise exception 'Question % contains an unknown matrix row or column.', v_question.id using errcode = '22023';
      end if;
      if v_effectively_required and (
        (select count(*) from pg_catalog.jsonb_object_keys(v_answer)) <> v_option_count
        or exists (
          select 1 from public.survey_question_options row_option
          where row_option.question_id = v_question.id
            and not (v_answer ? row_option.value)
        )
      ) then
        raise exception 'Question % requires one matrix-column answer for every row.', v_question.id
          using errcode = '22023';
      end if;
    elsif v_question.type = 'file_upload' then
      if pg_catalog.jsonb_typeof(v_answer) <> 'object'
         or pg_catalog.jsonb_typeof(v_answer -> 'bucket') <> 'string'
         or pg_catalog.jsonb_typeof(v_answer -> 'path') <> 'string'
         or pg_catalog.jsonb_typeof(v_answer -> 'originalName') <> 'string'
         or pg_catalog.jsonb_typeof(v_answer -> 'mimeType') <> 'string'
         or pg_catalog.jsonb_typeof(v_answer -> 'sizeBytes') <> 'number' then
        raise exception 'Question % requires a registered upload object.', v_question.id using errcode = '22023';
      end if;
      v_file_bucket := v_answer ->> 'bucket';
      v_file_path := v_answer ->> 'path';
      v_file_size := (v_answer ->> 'sizeBytes')::bigint;
      if v_question.settings ? 'maxFileSizeMb'
         and v_file_size > ((v_question.settings ->> 'maxFileSizeMb')::numeric * 1048576) then
        raise exception 'Question % exceeds its configured file-size limit.', v_question.id using errcode = '22023';
      end if;
      if not exists (
        select 1 from private.response_upload_objects u
        where u.survey_version_id = p_survey_version_id
          and u.bucket_id = v_file_bucket
          and u.object_path = v_file_path
          and u.original_filename = v_answer ->> 'originalName'
          and u.mime_type = v_answer ->> 'mimeType'
          and u.size_bytes = v_file_size
          and u.response_id is null
          and (
            u.owner_user_id = p_user_id
            or (v_privacy = 'anonymous' and u.owner_user_id is null)
          )
          and exists (
            select 1 from storage.objects stored_object
            where stored_object.bucket_id = u.bucket_id
              and stored_object.name = u.object_path
              and stored_object.metadata ->> 'size' ~ '^[0-9]+$'
              and (stored_object.metadata ->> 'size')::bigint = u.size_bytes
              and lower(coalesce(stored_object.metadata ->> 'mimetype', '')) = u.mime_type
          )
      ) then
        raise exception 'Question % references an upload that is missing, already used, or not owned by this respondent.',
          v_question.id using errcode = '22023';
      end if;
    elsif v_question.type in ('map_tiles', 'map_markup', 'map_polygon') then
      if pg_catalog.jsonb_typeof(v_answer) <> 'object' then
        raise exception 'Question % requires a structured map answer.', v_question.id using errcode = '22023';
      end if;
      select mv.version_number, mv.map_asset_id, mv.source_kind
      into v_map_version_number, v_map_asset_id, v_map_source_kind
      from public.map_versions mv where mv.id = v_question.map_version_id;
      if v_answer ->> 'mapId' is distinct from v_map_asset_id::text
         or pg_catalog.jsonb_typeof(v_answer -> 'mapVersion') <> 'number'
         or (v_answer ->> 'mapVersion')::numeric <> pg_catalog.trunc((v_answer ->> 'mapVersion')::numeric)
         or (v_answer ->> 'mapVersion')::integer <> v_map_version_number then
        raise exception 'Question % references the wrong map or map version.', v_question.id using errcode = '22023';
      end if;
      if v_question.type = 'map_tiles' then
        v_selected := v_answer -> 'selectedRegionIds';
        if pg_catalog.jsonb_typeof(v_selected) <> 'array'
           or pg_catalog.jsonb_array_length(v_selected) > 1000
           or (v_question.required and pg_catalog.jsonb_array_length(v_selected) = 0)
           or exists (
             select 1 from pg_catalog.jsonb_array_elements(v_selected) item(value)
             where pg_catalog.jsonb_typeof(item.value) <> 'string'
                or char_length(btrim(item.value #>> '{}')) not between 1 and 256
                or (
                  v_map_source_kind = 'static'
                  and not exists (
                  select 1 from public.map_regions mr
                  where mr.map_version_id = v_question.map_version_id
                    and mr.id::text = (item.value #>> '{}')
                  )
                )
           ) then
          raise exception 'Question % contains an invalid selectable-region answer.', v_question.id
            using errcode = '22023';
        end if;
        if (
          select count(*) from pg_catalog.jsonb_array_elements_text(v_selected)
        ) <> (
          select count(distinct item.value) from pg_catalog.jsonb_array_elements_text(v_selected) item(value)
        ) then
          raise exception 'Question % selects the same region more than once.', v_question.id using errcode = '22023';
        end if;
      else
        perform private.validate_normalized_points(
          v_answer -> 'rawStroke',
          'rawStroke for question ' || v_question.id::text,
          case when v_question.type = 'map_polygon' then 3 else 2 end
        );
        if v_answer ? 'derivedPolygon' then
          perform private.validate_normalized_points(
            v_answer -> 'derivedPolygon',
            'derivedPolygon for question ' || v_question.id::text,
            3
          );
        end if;
      end if;
    elsif v_question.type = 'information' then
      raise exception 'Information-only question % cannot store an answer.', v_question.id using errcode = '22023';
    end if;
  end loop;

  if exists (
    select 1
    from public.survey_questions q1
    join public.survey_questions q2
      on q2.survey_version_id = q1.survey_version_id
     and q2.id > q1.id
    where q1.survey_version_id = p_survey_version_id
      and q1.type = 'file_upload'
      and q2.type = 'file_upload'
      and p_answers -> q1.id::text ->> 'path' is not null
      and p_answers -> q1.id::text ->> 'path' = p_answers -> q2.id::text ->> 'path'
  ) then
    raise exception 'One uploaded object cannot be reused for two file-upload answers.' using errcode = '22023';
  end if;
end;
$$;

create or replace function public.create_response_upload_slot(
  p_survey_version_id uuid,
  p_original_filename text,
  p_mime_type text,
  p_size_bytes bigint
)
returns table (
  upload_id uuid,
  bucket_id text,
  object_path text
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_organization_id uuid;
  v_upload_id uuid := gen_random_uuid();
  v_safe_filename text;
  v_object_path text;
begin
  if v_user_id is null then
    raise exception 'Sign in before creating a browser upload slot.' using errcode = '42501';
  end if;
  if not public.can_access_survey_version(p_survey_version_id) then
    raise exception 'This survey is not currently available to this user.' using errcode = '42501';
  end if;
  if not exists (
    select 1 from public.survey_questions q
    where q.survey_version_id = p_survey_version_id and q.type = 'file_upload'
  ) then
    raise exception 'This survey does not contain a file-upload question.' using errcode = '22023';
  end if;
  if p_size_bytes < 1 or p_size_bytes > 52428800 then
    raise exception 'Upload size must be between 1 byte and 50 MB.' using errcode = '22023';
  end if;
  if char_length(btrim(p_original_filename)) < 1 or char_length(p_original_filename) > 255
     or char_length(btrim(p_mime_type)) < 1 or char_length(p_mime_type) > 200
     or p_mime_type ~ '[\r\n]' then
    raise exception 'Upload filename or MIME type is invalid.' using errcode = '22023';
  end if;

  select s.organization_id into v_organization_id
  from public.survey_versions sv
  join public.surveys s on s.id = sv.survey_id
  where sv.id = p_survey_version_id;

  v_safe_filename := left(
    pg_catalog.regexp_replace(btrim(p_original_filename), '[^A-Za-z0-9._-]+', '_', 'g'),
    180
  );
  if v_safe_filename in ('', '.', '..') then
    v_safe_filename := 'upload';
  end if;
  v_object_path := v_organization_id::text || '/' || p_survey_version_id::text || '/'
    || v_upload_id::text || '/' || v_safe_filename;

  insert into private.response_upload_objects (
    id, organization_id, survey_version_id, owner_user_id, bucket_id,
    object_path, original_filename, mime_type, size_bytes
  ) values (
    v_upload_id, v_organization_id, p_survey_version_id, v_user_id,
    'survey-response-uploads', v_object_path, p_original_filename,
    lower(btrim(p_mime_type)), p_size_bytes
  );

  return query select v_upload_id, 'survey-response-uploads'::text, v_object_path;
end;
$$;

create or replace function public.submit_survey_response(
  p_survey_version_id uuid,
  p_answers jsonb,
  p_device_token text default null,
  p_started_at timestamptz default null,
  p_metadata jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_version public.survey_versions%rowtype;
  v_survey public.surveys%rowtype;
  v_response_id uuid := gen_random_uuid();
  v_pseudonym_id uuid;
  v_dedupe_hash text;
  v_existing_response_id uuid;
begin
  if p_answers is null or pg_catalog.jsonb_typeof(p_answers) <> 'object' then
    raise exception 'Answers must be a JSON object keyed by question id.' using errcode = '22023';
  end if;
  if p_metadata is null or pg_catalog.jsonb_typeof(p_metadata) <> 'object' then
    raise exception 'Response metadata must be a JSON object.' using errcode = '22023';
  end if;
  if pg_catalog.pg_column_size(p_answers) > 10485760 then
    raise exception 'The response payload exceeds the 10 MB database limit.' using errcode = '54000';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_survey_version_id::text, 0));
  select sv.* into v_version from public.survey_versions sv where sv.id = p_survey_version_id;
  if not found then
    raise exception 'Survey version not found.' using errcode = 'P0002';
  end if;
  select s.* into v_survey from public.surveys s where s.id = v_version.survey_id;

  if not public.can_access_survey_version(p_survey_version_id) then
    raise exception 'This survey is not currently accepting responses from this user.' using errcode = '42501';
  end if;
  if v_version.privacy in ('pseudonymous', 'identified') and v_user_id is null then
    raise exception 'This privacy mode requires a signed-in respondent.' using errcode = '42501';
  end if;
  if exists (
    select 1
    from pg_catalog.jsonb_object_keys(p_answers) as answer_key
    where not exists (
      select 1 from public.survey_questions q
      where q.survey_version_id = v_version.id and q.id::text = answer_key
    )
  ) then
    raise exception 'The response contains an answer for a question outside this survey version.'
      using errcode = '22023';
  end if;

  perform private.validate_survey_answers(v_version.id, p_answers, v_user_id);

  if v_version.privacy = 'pseudonymous' then
    if v_version.pseudonymous_linking_enabled then
      insert into private.organization_user_pseudonyms (organization_id, user_id)
      values (v_survey.organization_id, v_user_id)
      on conflict (organization_id, user_id) do nothing;
      select p.pseudonym_id into v_pseudonym_id
      from private.organization_user_pseudonyms p
      where p.organization_id = v_survey.organization_id and p.user_id = v_user_id;
    else
      insert into private.survey_version_user_pseudonyms (survey_version_id, user_id)
      values (v_version.id, v_user_id)
      on conflict (survey_version_id, user_id) do nothing;
      select p.pseudonym_id into v_pseudonym_id
      from private.survey_version_user_pseudonyms p
      where p.survey_version_id = v_version.id and p.user_id = v_user_id;
    end if;
  end if;

  if v_version.duplicate_policy = 'one_per_account' then
    if v_version.privacy = 'anonymous' then
      raise exception 'Anonymous surveys cannot use account-based duplicate enforcement.' using errcode = '23514';
    elsif v_user_id is null then
      raise exception 'One response per account requires the respondent to sign in.' using errcode = '42501';
    end if;
    v_dedupe_hash := pg_catalog.encode(
      extensions.digest(
        pg_catalog.convert_to(v_version.id::text || ':account:' || v_user_id::text, 'UTF8'),
        'sha256'
      ), 'hex'
    );
  elsif v_version.duplicate_policy = 'one_per_device' then
    if nullif(p_device_token, '') is null then
      raise exception 'A browser device token is required for this duplicate policy.' using errcode = '22023';
    end if;
    v_dedupe_hash := pg_catalog.encode(
      extensions.digest(
        pg_catalog.convert_to(v_version.id::text || ':device:' || p_device_token, 'UTF8'),
        'sha256'
      ), 'hex'
    );
  elsif v_version.duplicate_policy = 'replace_previous' then
    if v_version.privacy = 'anonymous' then
      if nullif(p_device_token, '') is null then
        raise exception 'Replacing a previous anonymous response requires a browser device token.' using errcode = '22023';
      end if;
      v_dedupe_hash := pg_catalog.encode(
        extensions.digest(
          pg_catalog.convert_to(v_version.id::text || ':device:' || p_device_token, 'UTF8'),
          'sha256'
        ), 'hex'
      );
    elsif v_user_id is not null then
      v_dedupe_hash := pg_catalog.encode(
        extensions.digest(
          pg_catalog.convert_to(v_version.id::text || ':account:' || v_user_id::text, 'UTF8'),
          'sha256'
        ), 'hex'
      );
    elsif nullif(p_device_token, '') is not null then
      v_dedupe_hash := pg_catalog.encode(
        extensions.digest(
          pg_catalog.convert_to(v_version.id::text || ':device:' || p_device_token, 'UTF8'),
          'sha256'
        ), 'hex'
      );
    else
      raise exception 'Replacing a previous response requires a login or browser device token.' using errcode = '22023';
    end if;
  end if;

  if v_dedupe_hash is not null then
    select d.response_id into v_existing_response_id
    from private.response_deduplication d
    where d.survey_version_id = v_version.id
      and d.dedupe_key_hash = v_dedupe_hash
      and d.active
    for update;

    if found and v_version.duplicate_policy <> 'replace_previous' then
      raise exception 'A response already exists under this survey’s duplicate policy.' using errcode = '23505';
    elsif found then
      update private.response_deduplication set active = false
      where response_id = v_existing_response_id;
    end if;
  end if;

  -- A true replacement does not consume another response-limit slot. The
  -- advisory lock above serializes this count with competing submissions.
  if v_existing_response_id is null
     and v_version.response_limit is not null
     and (
       select count(*) from public.survey_responses r
       where r.survey_version_id = v_version.id and r.status = 'submitted'
     ) >= v_version.response_limit then
    raise exception 'This survey has reached its response limit.' using errcode = '55000';
  end if;

  insert into public.survey_responses (
    id, organization_id, survey_id, survey_version_id, privacy, pseudonym_id,
    answers, started_at, metadata
  ) values (
    v_response_id, v_survey.organization_id, v_survey.id, v_version.id,
    v_version.privacy, v_pseudonym_id, p_answers, p_started_at,
    p_metadata - array['email', 'user_id', 'name', 'display_name', 'device_token']
  );

  if v_version.privacy = 'identified' then
    insert into private.response_identities (response_id, user_id)
    values (v_response_id, v_user_id);
  end if;

  update private.response_upload_objects u
  set response_id = v_response_id,
      attached_at = pg_catalog.now(),
      owner_user_id = case when v_version.privacy = 'identified' then u.owner_user_id else null end
  from public.survey_questions q
  where q.survey_version_id = v_version.id
    and q.type = 'file_upload'
    and u.survey_version_id = v_version.id
    and u.response_id is null
    and u.bucket_id = p_answers -> q.id::text ->> 'bucket'
    and u.object_path = p_answers -> q.id::text ->> 'path';

  if v_dedupe_hash is not null then
    insert into private.response_deduplication (
      response_id, survey_version_id, dedupe_key_hash
    ) values (v_response_id, v_version.id, v_dedupe_hash);
  end if;

  if v_existing_response_id is not null then
    update public.survey_responses
    set status = 'superseded', superseded_by = v_response_id
    where id = v_existing_response_id;
  end if;

  if v_user_id is not null then
    update public.survey_assignments
    set status = 'completed',
        completed_at = pg_catalog.now(),
        completion_response_id = case when v_version.privacy = 'identified' then v_response_id else null end
    where survey_version_id = v_version.id
      and user_id = v_user_id
      and status <> 'cancelled';
    delete from public.response_drafts
    where survey_version_id = v_version.id and owner_user_id = v_user_id;
  end if;

  -- Queue only answer-free delivery metadata. A trusted worker can send an
  -- immediate notice or aggregate summary events without ever loading the
  -- respondent's answers or identity mapping.
  if coalesce(v_version.notification_config ->> 'mode', 'none') in ('each', 'summary') then
    insert into private.notification_outbox (organization_id, event_type, payload)
    values (
      v_survey.organization_id,
      case v_version.notification_config ->> 'mode'
        when 'each' then 'survey.response_submitted'
        else 'survey.response_summary_increment'
      end,
      pg_catalog.jsonb_build_object(
        'survey_id', v_survey.id,
        'survey_version_id', v_version.id,
        'response_id', v_response_id,
        'notification_mode', v_version.notification_config ->> 'mode'
      )
    );
  end if;

  return v_response_id;
end;
$$;

create or replace function public.get_survey_responses(p_survey_version_id uuid)
returns table (
  response_id uuid,
  started_at timestamptz,
  submitted_at timestamptz,
  response_status public.response_status,
  superseded_by_response_id uuid,
  invalidation_reason text,
  privacy public.privacy_mode,
  pseudonym_id uuid,
  respondent_user_id uuid,
  respondent_email text,
  respondent_display_name text,
  answers jsonb
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_organization_id uuid;
begin
  select s.organization_id into v_organization_id
  from public.survey_versions sv
  join public.surveys s on s.id = sv.survey_id
  where sv.id = p_survey_version_id;

  if v_organization_id is null or not public.has_org_role(
    v_organization_id,
    array['owner', 'admin', 'response_viewer']::public.organization_role[]
  ) then
    raise exception 'You do not have permission to view these responses.' using errcode = '42501';
  end if;

  return query
  select
    r.id,
    r.started_at,
    r.submitted_at,
    r.status,
    r.superseded_by,
    r.invalidation_reason,
    r.privacy,
    r.pseudonym_id,
    case when r.privacy = 'identified' then ri.user_id else null end,
    case when r.privacy = 'identified' then u.email else null end,
    case when r.privacy = 'identified' then p.display_name else null end,
    r.answers
  from public.survey_responses r
  left join private.response_identities ri on ri.response_id = r.id and r.privacy = 'identified'
  left join auth.users u on u.id = ri.user_id
  left join public.profiles p on p.id = ri.user_id
  where r.survey_version_id = p_survey_version_id
  order by r.submitted_at desc;
end;
$$;

create or replace function public.list_published_survey_versions_for_responses(p_organization_id uuid)
returns table (
  survey_version_id uuid,
  survey_id uuid,
  organization_id uuid,
  version_number integer,
  survey_title text,
  privacy public.privacy_mode,
  published_at timestamptz
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.has_org_role(
    p_organization_id,
    array['owner', 'admin', 'response_viewer']::public.organization_role[]
  ) then
    raise exception 'You do not have permission to view these response versions.' using errcode = '42501';
  end if;

  return query
  select
    sv.id,
    s.id,
    s.organization_id,
    sv.version_number,
    sv.title,
    sv.privacy,
    sv.published_at
  from public.survey_versions sv
  join public.surveys s on s.id = sv.survey_id
  where s.organization_id = p_organization_id
    and sv.status = 'published'
  order by sv.published_at desc, sv.version_number desc;
end;
$$;

-- Response viewers need immutable question labels and answer-choice meanings
-- for historical responses, including versions that are no longer open. This
-- role-gated RPC exposes only response-interpretation metadata—not builder
-- permissions, conditional logic, map geometry, files, or integration data.
create or replace function public.get_published_response_schema(p_organization_id uuid)
returns table (
  survey_version_id uuid,
  question_id uuid,
  question_position integer,
  question_type public.question_type,
  question_title text,
  question_description text,
  question_required boolean,
  map_version_id uuid,
  question_settings jsonb,
  option_definitions jsonb,
  map_name text,
  map_region_definitions jsonb
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.has_org_role(
    p_organization_id,
    array['owner', 'admin', 'response_viewer']::public.organization_role[]
  ) then
    raise exception 'You do not have permission to view response question definitions.' using errcode = '42501';
  end if;

  return query
  select
    sv.id,
    q.id,
    q.position,
    q.type,
    q.title,
    q.description,
    q.required,
    q.map_version_id,
    q.settings,
    coalesce((
      select pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
          'id', o.id,
          'position', o.position,
          'label', o.label,
          'value', o.value
        ) order by o.position
      )
      from public.survey_question_options o
      where o.question_id = q.id
    ), '[]'::pg_catalog.jsonb),
    ma.name,
    coalesce((
      select pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
          'id', mr.id,
          'label', mr.label
        ) order by mr.label, mr.id
      )
      from public.map_regions mr
      where mr.map_version_id = q.map_version_id
    ), '[]'::pg_catalog.jsonb)
  from public.survey_versions sv
  join public.surveys s on s.id = sv.survey_id
  join public.survey_questions q on q.survey_version_id = sv.id
  left join public.map_versions mv on mv.id = q.map_version_id
  left join public.map_assets ma on ma.id = mv.map_asset_id
  where s.organization_id = p_organization_id
    and sv.status = 'published'
  order by sv.published_at desc, sv.version_number desc, q.position;
end;
$$;

-- Stable public API names used by the application and deployment smoke tests.
create or replace function public.platform_healthcheck()
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select pg_catalog.jsonb_build_object(
    'ok', true,
    'schema_version', '0001_initial',
    'checked_at', pg_catalog.clock_timestamp()
  );
$$;

create or replace function public.request_membership_by_code(p_code text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_organization_id uuid;
  v_match_count integer;
  v_matches uuid[];
  v_membership_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Sign in before requesting membership.' using errcode = '42501';
  end if;

  select pg_catalog.array_agg(c.organization_id)
  into v_matches
  from public.organization_join_codes c
  where c.is_active
    and (c.expires_at is null or c.expires_at > pg_catalog.now())
    and (
      c.max_uses is null
      or c.use_count < c.max_uses
      or exists (
        select 1
        from public.organization_memberships m
        join public.membership_requests mr on mr.membership_id = m.id
        where m.organization_id = c.organization_id
          and m.user_id = auth.uid()
          and mr.join_code_id = c.id
      )
    )
    and c.code_hash = extensions.crypt(upper(btrim(p_code)), c.code_hash);

  v_match_count := coalesce(pg_catalog.cardinality(v_matches), 0);
  if v_match_count > 0 then
    v_organization_id := v_matches[1];
  end if;

  if v_match_count = 0 then
    raise exception 'This join code is invalid, expired, disabled, or has reached its use limit.' using errcode = '22023';
  elsif v_match_count > 1 then
    raise exception 'This code matches more than one organization. Ask an administrator to rotate it.' using errcode = '22023';
  end if;

  select public.request_membership_with_code(v_organization_id, p_code)
  into v_membership_id;
  return v_membership_id;
end;
$$;

create or replace function public.accept_invitation(p_token text)
returns uuid
language sql
security definer
set search_path = ''
as $$
  select public.accept_organization_invitation(p_token);
$$;

create or replace function public.final_publish_survey_version(p_survey_version_id uuid)
returns uuid
language sql
security definer
set search_path = ''
as $$
  select public.publish_survey_version(p_survey_version_id);
$$;

create or replace function public.edit_published_survey_copy(p_survey_version_id uuid)
returns uuid
language sql
security definer
set search_path = ''
as $$
  select public.copy_published_survey_version(p_survey_version_id);
$$;

-- ---------------------------------------------------------------------------
-- Private Supabase Storage buckets and object policies
-- ---------------------------------------------------------------------------

insert into storage.buckets (
  id, name, public, file_size_limit, allowed_mime_types
) values
  (
    'survey-static-maps',
    'survey-static-maps',
    false,
    52428800,
    array[
      'image/png', 'image/jpeg', 'image/webp', 'image/gif',
      'image/svg+xml', 'image/tiff', 'application/pdf'
    ]::text[]
  ),
  (
    'survey-response-uploads',
    'survey-response-uploads',
    false,
    52428800,
    null
  )
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

alter table storage.objects enable row level security;

create policy static_map_objects_read
  on storage.objects for select to anon, authenticated
  using (
    bucket_id = 'survey-static-maps'
    and (
      public.can_read_static_map_object(bucket_id, name)
      or public.can_manage_static_map_object(bucket_id, name)
    )
  );

create policy static_map_objects_insert
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'survey-static-maps'
    and public.can_manage_static_map_object(bucket_id, name)
  );

create policy static_map_objects_update
  on storage.objects for update to authenticated
  using (
    bucket_id = 'survey-static-maps'
    and public.can_manage_static_map_object(bucket_id, name)
  )
  with check (
    bucket_id = 'survey-static-maps'
    and public.can_manage_static_map_object(bucket_id, name)
  );

create policy static_map_objects_delete
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'survey-static-maps'
    and public.can_manage_static_map_object(bucket_id, name)
  );

create policy response_upload_objects_read
  on storage.objects for select to authenticated
  using (
    bucket_id = 'survey-response-uploads'
    and public.can_read_response_upload_object(bucket_id, name)
  );

create policy response_upload_objects_insert
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'survey-response-uploads'
    and public.can_write_response_upload_object(bucket_id, name)
  );

create policy response_upload_objects_update
  on storage.objects for update to authenticated
  using (
    bucket_id = 'survey-response-uploads'
    and public.can_write_response_upload_object(bucket_id, name)
  )
  with check (
    bucket_id = 'survey-response-uploads'
    and public.can_write_response_upload_object(bucket_id, name)
  );

create policy response_upload_objects_delete
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'survey-response-uploads'
    and public.can_delete_response_upload_object(bucket_id, name)
  );

-- ---------------------------------------------------------------------------
-- Explicit API privileges
-- ---------------------------------------------------------------------------

alter table private.organization_user_pseudonyms enable row level security;
alter table private.survey_version_user_pseudonyms enable row level security;
alter table private.response_identities enable row level security;
alter table private.response_deduplication enable row level security;
alter table private.response_upload_objects enable row level security;
alter table private.notification_outbox enable row level security;

revoke all on all tables in schema private from public, anon, authenticated;
revoke all on all functions in schema private from public, anon, authenticated;
revoke all on all tables in schema public from anon, authenticated;
revoke all on all functions in schema public from public, anon, authenticated;

-- Trusted Edge Functions and scheduled workers use service_role. This grant is
-- intentionally powerful and is why that key must never reach a browser.
grant usage on schema private to service_role;
grant select, insert, update, delete on all tables in schema private to service_role;

grant usage on schema storage to anon, authenticated;
grant select on storage.objects to anon, authenticated;
grant insert, update, delete on storage.objects to authenticated;

grant select, insert, update, delete on all tables in schema public to authenticated;
grant usage, select on all sequences in schema public to authenticated;
-- Stable survey identities may only be hard-deleted through the reviewed
-- security-definer lifecycle functions below. RLS alone is not a substitute
-- for this table-level privilege boundary.
revoke delete on public.surveys from authenticated;

grant select on
  public.organizations,
  public.setting_definitions,
  public.map_assets,
  public.map_versions,
  public.map_regions,
  public.surveys,
  public.survey_versions,
  public.survey_version_setting_values,
  public.survey_questions,
  public.survey_question_options,
  public.survey_map_trigger_areas,
  public.survey_logic_rules
to anon;

-- Public read policies short-circuit through this membership predicate before
-- their respondent-access branch. Anonymous callers need execute permission;
-- auth.uid() is null for them, so the function can only return false.
grant execute on function public.has_org_role(uuid, public.organization_role[]) to anon, authenticated;
grant execute on function public.is_org_member(uuid) to anon, authenticated;
grant execute on function public.can_access_survey_version(uuid) to anon, authenticated;
grant execute on function public.get_survey_organization_display(uuid) to anon, authenticated;
grant execute on function public.get_survey_mapbox_integration(uuid) to anon, authenticated;
grant execute on function public.get_public_organization_profile(text) to anon, authenticated;
grant execute on function public.get_membership_organization_display(uuid) to authenticated;
grant execute on function public.get_membership_account_identities(uuid) to authenticated;
grant execute on function public.can_read_map_version(uuid) to anon, authenticated;
grant execute on function public.can_read_map_asset(uuid) to anon, authenticated;
grant execute on function public.can_read_static_map_object(text, text) to anon, authenticated;
grant execute on function public.can_manage_static_map_object(text, text) to authenticated;
grant execute on function public.can_write_response_upload_object(text, text) to authenticated;
grant execute on function public.can_read_response_upload_object(text, text) to authenticated;
grant execute on function public.can_delete_response_upload_object(text, text) to authenticated;
grant execute on function public.platform_healthcheck() to anon, authenticated;
grant execute on function public.create_organization(text, text, text, text, text, text) to authenticated;
grant execute on function public.create_organization_invitation(
  uuid, text, public.organization_role
) to authenticated;
grant execute on function public.accept_organization_invitation(text) to authenticated;
grant execute on function public.rotate_organization_join_code(
  uuid, text, text, timestamptz, integer, boolean, boolean
) to authenticated;
grant execute on function public.request_membership_with_code(uuid, text) to authenticated;
grant execute on function public.request_membership_by_code(text) to authenticated;
grant execute on function public.set_current_join_code_active(uuid, boolean) to authenticated;
grant execute on function public.accept_invitation(text) to authenticated;
grant execute on function public.review_membership_request(
  uuid, public.membership_status, public.organization_role
) to authenticated;
grant execute on function public.publish_survey_version(uuid) to authenticated;
grant execute on function public.copy_published_survey_version(uuid) to authenticated;
grant execute on function public.final_publish_survey_version(uuid) to authenticated;
grant execute on function public.edit_published_survey_copy(uuid) to authenticated;
grant execute on function public.archive_survey(uuid) to authenticated;
grant execute on function public.delete_survey(uuid) to authenticated;
grant execute on function public.restore_deleted_survey(uuid) to authenticated;
grant execute on function public.get_survey_deletion_uploads(uuid) to authenticated;
grant execute on function public.permanently_delete_survey(uuid) to authenticated;
grant execute on function public.list_due_survey_deletions(integer) to service_role;
grant execute on function public.purge_due_deleted_surveys(integer) to service_role;
grant execute on function public.create_response_upload_slot(uuid, text, text, bigint) to authenticated;
grant execute on function public.submit_survey_response(
  uuid, jsonb, text, timestamptz, jsonb
) to anon, authenticated;
grant execute on function public.get_survey_responses(uuid) to authenticated;
grant execute on function public.list_published_survey_versions_for_responses(uuid) to authenticated;
grant execute on function public.get_published_response_schema(uuid) to authenticated;

commit;
