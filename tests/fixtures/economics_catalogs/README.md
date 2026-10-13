# Step 11's catalog fixtures

**Every file here is format-faithful, NOT a recorded response; replace with a recording (owner).**

They were written by hand, from each provider's format as the builder knew it, because
no request to a provider or its documentation could be made while MVP step 11 was built
(`docs/economics/spec-v1.md`, section 30). The first line of each file says so, and the
tests take that line off before an adapter reads the file. A recording that replaces a
file needs no change to the tests: each adapter has a structure test that pins the
format its fixture is written in, so a recording that differs fails there, loudly,
rather than parsing silently; the value tests read each fixture's own values with a
reader of their own.

**Every company, respondent, bank and person named here is FICTITIOUS ("Fixture ..."),
and every amount, price and date is made up.** The CIK `0009999999` and the ticker
`FXMP` are placeholders. These files show formats, not facts.

| File | Source key | The request it answers | Status |
|---|---|---|---|
| `aws-price-list-s3-us-east-1.json` | `aws-price-list-s3-us-east-1` | `GET https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/current/us-east-1/index.json` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `azure-retail-prices-site-recovery-eastus-p1.json`, `-p2.json` | `azure-retail-prices-site-recovery-eastus` | `GET https://prices.azure.com/api/retail/prices?api-version=2023-01-01-preview&$filter=serviceName eq 'Azure Site Recovery' and armRegionName eq 'eastus' and priceType eq 'Consumption'`, then its `NextPageLink` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `gcp-billing-catalog-cloud-storage-p1.json`, `-p2.json` | `gcp-billing-catalog-cloud-storage` | `GET https://cloudbilling.googleapis.com/v1/services/95FF-2EF5-5EA1/skus?currencyCode=USD&pageSize=5000&key=<ECONOMICS_GCP_BILLING_API_KEY>`, then `&pageToken=<nextPageToken>` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `sec-edgar-submissions-cik0009999999.json` | `sec-edgar-submissions-cik0009999999` | `GET https://data.sec.gov/submissions/CIK0009999999.json`, `User-Agent: <ECONOMICS_SEC_USER_AGENT>` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `sec-edgar-companyfacts-cik0009999999.json` | `sec-edgar-companyfacts-cik0009999999` | `GET https://data.sec.gov/api/xbrl/companyfacts/CIK0009999999.json`, the same header | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `sec-edgar-segments-cik0009999999.xml` | `sec-edgar-segments-cik0009999999` | `GET https://www.sec.gov/Archives/edgar/data/9999999/000999999926000033/exmp-20260627_htm.xml` (the newest periodic inline-XBRL filing's instance), the same header | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `cfpb-enforcement-actions.xml` | `cfpb-enforcement-actions` | `GET https://www.consumerfinance.gov/enforcement/actions/feed/` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `ftc-privacy-security-cases.xml` | `ftc-privacy-security-cases` | `GET https://www.ftc.gov/feeds/cases-proceedings/privacy-security.xml` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `sec-litigation-releases.xml` | `sec-litigation-releases` | `GET https://www.sec.gov/enforcement-litigation/litigation-releases/rss` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `hhs-ocr-hipaa-enforcement.xml` | `hhs-ocr-hipaa-enforcement` | `GET https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/rss.xml` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `occ-enforcement-actions.csv` | `occ-enforcement-actions` | `GET https://apps.occ.gov/EASearch/Search/ExportCsv` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `fdic-enforcement-orders.csv` | `fdic-enforcement-orders` | `GET https://orders.fdic.gov/s/enforcement-orders.csv` | format-faithful, NOT a recorded response; replace with a recording (owner) |
| `frb-enforcement-actions.csv` | `frb-enforcement-actions` | `GET https://www.federalreserve.gov/supervisionreg/files/enforcementactions.csv` | format-faithful, NOT a recorded response; replace with a recording (owner) |

## What each assumes, which a recording confirms or corrects

How sure the builder was differs by family, and the registry's dataset text says
"endpoint and format assumed: confirm with a recording (owner)" where it was least
sure.

- **AWS Price List** (well known): the bulk offer file's fields (`formatVersion`
  `v1.0`, `products`, `terms.OnDemand`, `priceDimensions`, `pricePerUnit.USD`) and the
  regional file's URL. The size of S3's us-east-1 file (the cap is 32 MiB). Whether
  every product of a regional file states `regionCode` (the adapter refuses another
  region where one is stated).
- **Azure Retail Prices** (well known): the page fields, `NextPageLink` with a `$skip`,
  prices as JSON numbers (read as `Decimal` from their text), `api-version`
  `2023-01-01-preview`. The service name `Azure Site Recovery`, and how many pages its
  eastus prices take (the cap is 20).
- **Google Cloud Billing Catalog** (well known): the SKU fields, `google.type.Money`
  (`units` as text, `nanos`, each absent when zero, as proto3 JSON writes it),
  `nextPageToken` (absent or empty on the last page). The service id
  `95FF-2EF5-5EA1` for Cloud Storage.
- **SEC EDGAR** (well known): the submissions JSON's columnar `filings.recent` and its
  top-level fields (the adapter refuses a field it does not know: a recording that
  holds another one adds it to `SUBMISSIONS_OPTIONAL`), and companyfacts' `units`
  lists. `companyfacts` holds no dimensioned fact, so segment revenue is read from the
  newest periodic filing's XBRL instance; the instance's name is the inline-XBRL
  primary document's with `_htm.xml` for `.htm`, which EDGAR's own extraction writes.
  The segment axis read is `us-gaap:StatementBusinessSegmentsAxis`.
- **Enforcement** (ASSUMED, the least certain): the builder knew of no documented,
  machine-readable enforcement listing with stated penalty fields for these agencies.
  The endpoints above are assumptions. CFPB, FTC, SEC and HHS OCR are read as RSS 2.0
  (a standard format): the respondent is the item's title for CFPB, FTC and SEC, whose
  pages are titled by respondent, and none for HHS OCR, whose titles are prose; no
  amount is in a field of an RSS item, so none is read. OCC, FDIC and the Federal
  Reserve are read as CSV exports whose columns are each source's `header` in the
  registry: the OCC's `Amount` is a civil money penalty or restitution by the row's
  `Type of Action`. A recording that differs is refused (`feed_malformed`) until the
  registry's columns are corrected.
