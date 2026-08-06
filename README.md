# Common Ground Survey Studio

This repository publishes a Common Ground organization website with GitHub Pages. The guided setup connects the website to an organization-controlled Supabase project, creates the first administrator account, and opens the survey dashboard.

## Start organization setup

Open the [Common Ground setup website](https://yana-157.github.io/common-ground-survey-studio-template/) and choose **Set up an organization**. The interface explains each GitHub and Supabase setting and links directly to the page where it is configured.

The website setup covers:

- creating the organization’s website repository from this prepared template;
- creating and checking the Supabase database;
- publishing the organization’s GitHub Pages website;
- creating the first password-protected administrator account; and
- opening the organization dashboard to build surveys, manage maps, invite members, and review responses.

Survey response data, accounts, and protected files are stored in the organization’s Supabase project. The repository contains the published website, its GitHub workflows, and the database setup used by the guided process.

## Repository workflows

- **Deploy Common Ground website** publishes the organization website after the two browser-safe Supabase values are added in GitHub Actions variables.
- **Purge surveys after 30 days** permanently removes surveys whose Recently Deleted recovery period has ended after its protected Supabase cleanup values are added in GitHub Actions secrets.
- **Build optional Mapbox tileset** creates a Census geography tileset when an organization chooses to configure Mapbox maps.

Never place a Supabase Secret key, service-role key, database password, Census API key, or Mapbox secret token in the website folder or GitHub Actions variables. The guided setup identifies the separate GitHub Actions secrets fields used for private credentials.
