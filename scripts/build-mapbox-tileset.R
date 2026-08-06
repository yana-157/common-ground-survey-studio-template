#!/usr/bin/env Rscript

# Build the optional Mapbox geography used by map-based survey questions.
#
# This is a parameterized adaptation of the Census -> Tippecanoe -> Mapbox
# workflow used by Cory McCartan's neighborhood-survey project. Organization
# and geography details live in a non-secret JSON config; API credentials must
# only be supplied through environment variables.

suppressPackageStartupMessages({
  library(jsonlite)
  library(sf)
})

options(tigris_use_cache = TRUE)

`%||%` <- function(value, fallback) {
  if (is.null(value) || length(value) == 0) fallback else value
}

stop_with <- function(message) {
  stop(message, call. = FALSE)
}

parse_boolean <- function(value, argument_name) {
  normalized <- tolower(as.character(value))
  if (normalized %in% c("true", "1", "yes")) return(TRUE)
  if (normalized %in% c("false", "0", "no")) return(FALSE)
  stop_with(sprintf("%s must be true or false.", argument_name))
}

parse_arguments <- function(arguments) {
  parsed <- list(config = NULL, upload = FALSE, output_dir = NULL)
  index <- 1

  while (index <= length(arguments)) {
    argument <- arguments[[index]]
    if (!argument %in% c("--config", "--upload", "--output-dir")) {
      stop_with(sprintf("Unknown argument: %s", argument))
    }
    if (index == length(arguments)) {
      stop_with(sprintf("Missing value for %s", argument))
    }

    value <- arguments[[index + 1]]
    if (argument == "--config") parsed$config <- value
    if (argument == "--upload") parsed$upload <- parse_boolean(value, "--upload")
    if (argument == "--output-dir") parsed$output_dir <- value
    index <- index + 2
  }

  if (is.null(parsed$config)) {
    stop_with(
      "Usage: Rscript scripts/build-mapbox-tileset.R --config <config.json> [--upload true|false] [--output-dir <directory>]"
    )
  }

  parsed
}

require_value <- function(value, field_name) {
  if (is.null(value) || length(value) == 0 || identical(trimws(as.character(value)), "")) {
    stop_with(sprintf("Config field '%s' is required.", field_name))
  }
  value
}

resolve_config_path <- function(path, config_directory) {
  if (grepl("^(/|[A-Za-z]:[/\\\\])", path)) return(path)
  file.path(config_directory, path)
}

download_census_geography <- function(census_config, census_api_key) {
  dataset <- census_config$dataset %||% "decennial_pl"
  geography <- require_value(census_config$geography, "census.geography")
  state <- require_value(census_config$state, "census.state")
  year <- as.integer(require_value(census_config$year, "census.year"))
  counties <- census_config$counties
  variables <- census_config$variables

  if (is.null(variables) || length(variables) == 0) {
    stop_with("Config field 'census.variables' must contain at least one named Census variable.")
  }
  if (is.null(names(variables)) || any(names(variables) == "")) {
    stop_with("Every entry in 'census.variables' needs a plain-language name.")
  }

  common_arguments <- list(
    geography = geography,
    variables = unlist(variables),
    state = state,
    year = year,
    output = "wide",
    geometry = TRUE,
    key = census_api_key
  )
  if (!is.null(counties) && length(counties) > 0) {
    common_arguments$county <- unlist(counties)
  }

  message(sprintf("Downloading %s %s geography for %s...", year, geography, state))

  if (dataset == "decennial_pl") {
    common_arguments$sumfile <- "pl"
    return(do.call(tidycensus::get_decennial, common_arguments))
  }
  if (dataset == "decennial_dhc") {
    common_arguments$sumfile <- "dhc"
    return(do.call(tidycensus::get_decennial, common_arguments))
  }
  if (dataset %in% c("acs1", "acs5")) {
    common_arguments$survey <- dataset
    return(do.call(tidycensus::get_acs, common_arguments))
  }

  stop_with("census.dataset must be one of: decennial_pl, decennial_dhc, acs1, or acs5.")
}

load_boundary <- function(boundary_config, state, year, config_directory) {
  boundary_type <- require_value(boundary_config$type, "boundary.type")

  if (boundary_type == "census_place") {
    place_name <- require_value(boundary_config$name, "boundary.name")
    places <- tigris::places(state = state, cb = TRUE, year = year)
    exact_match <- places$NAME == place_name | places$NAMELSAD == place_name
    selected <- places[!is.na(exact_match) & exact_match, ]

    if (nrow(selected) == 0) {
      available <- paste(utils::head(sort(unique(places$NAMELSAD)), 12), collapse = ", ")
      stop_with(sprintf(
        "No Census place exactly matched '%s'. Example names in this state: %s",
        place_name,
        available
      ))
    }
    if (nrow(selected) > 1) {
      stop_with(sprintf("Census place '%s' matched more than one boundary.", place_name))
    }
    return(selected)
  }

  if (boundary_type == "bounding_box") {
    west <- as.numeric(require_value(boundary_config$west, "boundary.west"))
    south <- as.numeric(require_value(boundary_config$south, "boundary.south"))
    east <- as.numeric(require_value(boundary_config$east, "boundary.east"))
    north <- as.numeric(require_value(boundary_config$north, "boundary.north"))
    if (!(west < east && south < north)) {
      stop_with("Bounding-box coordinates must satisfy west < east and south < north.")
    }
    return(st_as_sf(st_as_sfc(st_bbox(
      c(xmin = west, ymin = south, xmax = east, ymax = north),
      crs = st_crs(4326)
    ))))
  }

  if (boundary_type == "geojson") {
    configured_path <- require_value(boundary_config$path, "boundary.path")
    boundary_path <- resolve_config_path(configured_path, config_directory)
    if (!file.exists(boundary_path)) {
      stop_with(sprintf("Boundary GeoJSON does not exist: %s", boundary_path))
    }
    boundary <- st_read(boundary_path, quiet = TRUE)
    if (nrow(boundary) == 0) stop_with("Boundary GeoJSON contains no features.")
    return(boundary)
  }

  stop_with("boundary.type must be census_place, bounding_box, or geojson.")
}

filter_to_boundary <- function(features, boundary, clip_features) {
  features <- st_make_valid(features)
  boundary <- st_make_valid(boundary)
  boundary <- st_transform(boundary, st_crs(features))
  boundary <- st_union(boundary)
  selected <- features[lengths(st_intersects(features, boundary)) > 0, ]

  if (nrow(selected) == 0) {
    stop_with("The configured boundary did not intersect any Census features.")
  }

  if (clip_features) {
    selected <- suppressWarnings(st_intersection(selected, boundary))
    selected <- selected[!st_is_empty(selected), ]
  }

  selected <- selected[!duplicated(selected$GEOID), ]
  st_transform(selected, 4326)
}

write_adjacency_graph <- function(features, output_path) {
  touching <- st_touches(features)
  ids <- as.character(features$GEOID)
  graph <- lapply(touching, function(indices) unname(ids[indices]))
  names(graph) <- ids
  write_json(graph, output_path, auto_unbox = TRUE, pretty = TRUE)
}

run_tippecanoe <- function(geojson_path, mbtiles_path, layer_name, min_zoom, max_zoom) {
  executable <- Sys.which("tippecanoe")
  if (identical(unname(executable), "")) {
    stop_with("tippecanoe is not installed or is not on PATH. See scripts/README.md.")
  }

  arguments <- c(
    "--force",
    "--output", shQuote(normalizePath(mbtiles_path, mustWork = FALSE)),
    "--layer", shQuote(layer_name),
    "--minimum-zoom", as.character(min_zoom),
    "--maximum-zoom", as.character(max_zoom),
    "--coalesce-densest-as-needed",
    "--detect-shared-borders",
    "--use-attribute-for-id=GEOID",
    shQuote(normalizePath(geojson_path, mustWork = TRUE))
  )
  status <- system2(executable, arguments)
  if (!identical(status, 0L)) {
    stop_with(sprintf("tippecanoe failed with exit status %s.", status))
  }
}

arguments <- parse_arguments(commandArgs(trailingOnly = TRUE))
config_path <- normalizePath(arguments$config, mustWork = TRUE)
config_directory <- dirname(config_path)
config <- fromJSON(config_path, simplifyVector = FALSE)

if (!identical(as.integer(config$schema_version %||% 1), 1L)) {
  stop_with("Unsupported config schema_version. This script currently supports version 1.")
}

census_api_key <- Sys.getenv("CENSUS_API_KEY")
if (identical(census_api_key, "")) {
  stop_with("CENSUS_API_KEY is not set. Add it as a GitHub Actions repository secret or local environment variable.")
}

map_config <- config$map %||% list()
census_config <- config$census %||% list()
boundary_config <- config$boundary %||% list()
output_config <- config$output %||% list()

map_name <- require_value(map_config$name, "map.name")
tileset_id <- require_value(map_config$tileset_id, "map.tileset_id")
mapbox_username <- require_value(map_config$mapbox_username, "map.mapbox_username")
source_layer <- map_config$source_layer %||% "survey_geography"
min_zoom <- as.integer(map_config$min_zoom %||% 10)
max_zoom <- as.integer(map_config$max_zoom %||% 14)
start_zoom <- as.numeric(map_config$start_zoom %||% min(max_zoom, 13))

if (!grepl("^[a-z0-9][a-z0-9_-]{0,31}$", tileset_id)) {
  stop_with("map.tileset_id must be 1-32 lowercase letters, numbers, underscores, or hyphens.")
}
if (min_zoom < 0 || max_zoom > 22 || min_zoom > max_zoom) {
  stop_with("Map zooms must satisfy 0 <= min_zoom <= max_zoom <= 22.")
}

configured_output <- output_config$directory %||% "generated/mapbox"
output_directory <- arguments$output_dir %||% configured_output
dir.create(output_directory, recursive = TRUE, showWarnings = FALSE)

features <- download_census_geography(census_config, census_api_key)
if (!"GEOID" %in% names(features)) stop_with("Census response did not contain a GEOID field.")

boundary <- load_boundary(
  boundary_config,
  census_config$state,
  as.integer(census_config$year),
  config_directory
)
clip_features <- isTRUE(boundary_config$clip_features %||% TRUE)
features <- filter_to_boundary(features, boundary, clip_features)
message(sprintf("Selected %s Census features inside the configured boundary.", nrow(features)))

geojson_path <- file.path(output_directory, paste0(tileset_id, ".geojson"))
mbtiles_path <- file.path(output_directory, paste0(tileset_id, ".mbtiles"))
graph_path <- file.path(output_directory, paste0(tileset_id, "-adjacency.json"))
spec_path <- file.path(output_directory, paste0(tileset_id, "-map-spec.json"))
manifest_path <- file.path(output_directory, paste0(tileset_id, "-build-manifest.json"))

st_write(features, geojson_path, driver = "GeoJSON", delete_dsn = TRUE, quiet = TRUE)
write_adjacency_graph(features, graph_path)
run_tippecanoe(geojson_path, mbtiles_path, source_layer, min_zoom, max_zoom)

bounds <- st_bbox(features)
center <- c(
  unname((bounds[["xmin"]] + bounds[["xmax"]]) / 2),
  unname((bounds[["ymin"]] + bounds[["ymax"]]) / 2)
)
tileset_url <- sprintf("mapbox://%s.%s", mapbox_username, tileset_id)

map_spec <- list(
  schemaVersion = 1,
  provider = "mapbox",
  name = map_name,
  tilesetUrl = tileset_url,
  sourceLayer = source_layer,
  featureIdProperty = "GEOID",
  bounds = unname(c(bounds[["xmin"]], bounds[["ymin"]], bounds[["xmax"]], bounds[["ymax"]])),
  center = center,
  startZoom = start_zoom,
  minZoom = min_zoom,
  maxZoom = max_zoom,
  geography = list(
    censusDataset = census_config$dataset %||% "decennial_pl",
    censusYear = as.integer(census_config$year),
    unit = census_config$geography,
    state = census_config$state,
    counties = unname(unlist(census_config$counties %||% list())),
    boundaryType = boundary_config$type,
    featuresClippedToBoundary = clip_features
  ),
  adjacencyGraphFile = basename(graph_path),
  behaviorWhenMapboxIsUnavailable = "question_unavailable_no_static_fallback"
)
write_json(map_spec, spec_path, auto_unbox = TRUE, pretty = TRUE)

uploaded <- FALSE
if (arguments$upload) {
  mapbox_secret_token <- Sys.getenv("MAPBOX_SECRET_TOKEN")
  if (identical(mapbox_secret_token, "")) {
    stop_with("--upload true requires MAPBOX_SECRET_TOKEN with Mapbox upload permissions.")
  }

  message(sprintf("Uploading %s to %s...", basename(mbtiles_path), tileset_url))
  mapboxapi::upload_tiles(
    input = mbtiles_path,
    access_token = mapbox_secret_token,
    username = mapbox_username,
    tileset_id = tileset_id,
    tileset_name = map_name,
    multipart = TRUE
  )
  uploaded <- TRUE
}

manifest <- list(
  schemaVersion = 1,
  builtAt = format(Sys.time(), tz = "UTC", usetz = TRUE),
  configFile = basename(config_path),
  featureCount = nrow(features),
  tilesetUrl = tileset_url,
  uploadedToMapbox = uploaded,
  outputs = list(
    geojson = basename(geojson_path),
    mbtiles = basename(mbtiles_path),
    adjacencyGraph = basename(graph_path),
    mapSpec = basename(spec_path)
  )
)
write_json(manifest, manifest_path, auto_unbox = TRUE, pretty = TRUE)

message("Tileset build complete.")
message(sprintf("Artifacts: %s", normalizePath(output_directory)))
if (!uploaded) message("Mapbox upload was skipped; rerun with --upload true when the organization is ready.")
