"""The single registry of detector ids. Consumers import from here instead of re-listing them."""

# Detectors run by the monitoring engine (also the default delivery set).
ENGINE = ("large_upload", "upload_deviation")
# Announced once on open; never a "back to normal" send.
NEW_DEVICE = "new_device"
OPEN_ONLY = (NEW_DEVICE,)
ALL = ENGINE + OPEN_ONLY
