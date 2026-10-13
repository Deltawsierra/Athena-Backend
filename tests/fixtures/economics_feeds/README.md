# Economic Exposure feed fixtures (MVP step 10)

The answers the four live-feed adapters (`assurance/economics/engine/feeds.py`;
`docs/economics/spec-v1.md`, section 28) are tested against.

**Every file here is format-faithful, NOT a recorded response; replace with a recording (owner).**
Each was written by hand from the provider's documented response format. None was
fetched, and no number in any of them is a real published rate or index value. The
first line of each file says so (`# format-faithful, NOT a recorded response; replace
with a recording (owner)`), and the tests strip that one line before an adapter reads
the file. A recording that replaces a file carries no such line and is read as it is.
The adapters and the tests need no change. Each adapter has a structure test that
pins the format a file is written in, so a recording that differs fails loudly
(`tests/test_economics_feeds.py`, `test_<adapter>_fixture_structure`) and is not
parsed silently.

| File | Provider and format | The request it answers | Status |
|---|---|---|---|
| `ecb-eur-reference-rates.csv` | ECB Data Portal SDMX REST API, SDMX-CSV (`format=csvdata`), dataflow EXR | `GET https://data-api.ecb.europa.eu/service/data/EXR/D.GBP+JPY+USD.EUR.SP00.A?format=csvdata&lastNObservations=10` on 2026-10-13 | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `fed-h10-daily-rates.csv` | Federal Reserve Data Download Program, H.10 package, CSV (`label=include&layout=seriescolumn`) | `GET https://www.federalreserve.gov/datadownload/Output.aspx?rel=H10&series=60f32914ab61dfab590e0e470153e3ae&lastobs=10&from=&to=&filetype=csv&label=include&layout=seriescolumn&type=package` on 2026-10-13 | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `fred-cpiaucsl-2026-10-13.json` | FRED API `fred/series/observations`, JSON, the real-time window pinned to the as-of date (ALFRED) | `series_id=CPIAUCSL&file_type=json&realtime_start=2026-10-13&realtime_end=2026-10-13&observation_start=2025-09-01` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `fred-cpiaucsl-2026-06-30.json` | the same, an earlier vintage | the same, `realtime_start=realtime_end=2026-06-30&observation_start=2025-05-01` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `bls-ppi-final-demand.json` | BLS Public Data API, `timeseries/data`, JSON (v1 and v2 answer in this shape) | `POST https://api.bls.gov/publicAPI/v2/timeseries/data/` with `{"seriesid": ["WPUFD4"], "startyear": "2025", "endyear": "2026", "catalog": false, "registrationkey": <the owner's key>}` on 2026-10-13 | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `bls-ahe-total-private.json` | the same | the same, series `CES0500000003` | format-faithful, NOT a recorded response; replace with a recording (owner) |

What the files assume about each format, and so what a recording checks:

- ECB: the SDMX-CSV header with the 32 columns of the EXR dataflow, in the documented
  order. One line per observation, ordered by series and date. `KEY` is
  `EXR.D.<currency>.EUR.SP00.A`, the rate is `<currency>` per euro, `OBS_STATUS` is
  `A`, `UNIT_MULT` is `0`, and no line has a clock.
- H.10: six heading lines, labelled `Series Description`, `Unit:`, `Multiplier:`,
  `Currency:`, `Unique Identifier: ` and `Time Period`, then one line per business
  day. A day with no rate is `ND`. The euro and the pound are quoted in US dollars
  per unit (`RXI$US_N.B.EU`, unit `USD:_Per_EUR`; `RXI$US_N.B.UK`, unit
  `USD:_Per_GBP`), and the yen per US dollar (`RXI_N.B.JA`, `JPY:_Per_USD`). The
  unit spellings are the ones least certain without a recording: the reviewer of #161
  recalls the unit row as `Currency:_Per_EUR`, with the `Currency:` row naming the
  numerator. Until a recording shows which, the adapter fails closed
  (`feed_mismatch`); then it reads the convention from both rows. The DDP package id
  in the request is the H.10 package's, and an as-of request is assumed to list every
  weekday of its window (`ND` for a holiday). Both are to be confirmed by the owner's
  recording.
- FRED: the 13 documented top-level fields. Every observation carries the requested
  real-time window, and a month with no value is `.` (October 2025 here, as in the
  documented example's form).
- BLS: `status`, `responseTime`, `message` and `Results.series[]`, each value with
  `year`, `period` (`M01` to `M12`, `M13` for the annual average), `periodName`,
  `value` and `footnotes`, and `latest` on the newest. The PPI final-demand base,
  `2009-11=100`, is recorded in the registry and is for the owner to confirm.

To replace a file, record the request named above (with the owner's key where one
is needed: FRED, BLS v2) and save the answer's bytes, without the first-line note,
under the same name. Then run `tests/test_economics_feeds.py`. If the structure test
fails, the recording differs from the format assumed here: update the adapter and
this README together, never the test alone. The value tests read each file's own
values, so a recording's numbers need no edit to the tests.
