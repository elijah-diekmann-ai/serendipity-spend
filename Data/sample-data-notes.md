# Sample data notes (DC_OOP_05 Sep 2025)

This PDF appears to be a concatenated set of forwarded email receipts and trip summaries, not a single structured invoice.

## Observed receipt types
- Grab ride e-receipts (SGD)
- Uber trip summaries (USD and CAD)
- United Airlines inflight Wi-Fi purchase receipts (USD)
- Airline baggage fee payment receipt (CAD)

## Ingestion complications
- Multiple receipts per PDF; needs segmentation.
- Repeated forwarded email headers and "Begin forwarded message" blocks.
- Some items are trip summaries, not payment receipts.
- Multiple currencies and time zones in one file.
- Mixed distance units (miles vs kilometers).
- Charge breakdown fields vary by vendor and region.

## Generic fields to capture
- source_file_id, source_page, extraction_confidence
- vendor_name, receipt_type, category
- transaction_date, transaction_time, timezone
- amount_total, currency
- payment_method_last4 (if present)
- traveler_name (if present)
- raw_text_hash (for duplicate detection)
- email_from, email_to, email_subject, email_date (when email headers exist)

## Vendor-specific fields
### Grab
- ride_type (Premium, Standard/JustGrab)
- pickup_date
- booking_id
- breakdown: fare, platform_fee, driver_fee
- passenger_name
- profile (personal/business if present)
- paid_by_last4
- trip_distance + unit
- trip_duration
- pickup_location + time
- dropoff_location + time

### Uber
- ride_type (Black, Comfort)
- trip_date
- breakdown: trip_fare, booking_fee, airport_charges, tolls, taxes, surcharges
- pickup_location + time
- dropoff_location + time
- trip_distance + unit
- trip_duration
- driver_name (optional)
- rating (optional)
- receipt_type: trip_summary (not payment receipt)

### United (inflight Wi-Fi)
- item_description (Inflight Wi-Fi Basic/Premium)
- flight_number
- route (origin, destination)
- travel_date
- purchase_date
- total_amount + currency
- payment_method_last4
- traveler_name
- reference_number

### Airline baggage fee payment receipt
- pnr
- traveler_name
- fee_description (BAG FEE)
- fee_amount + taxes + total + currency
- payment_method_last4
- tax_ids (GST/QST) if present
- receipt_type: payment_receipt

## Policy-related signals to flag
- receipt_type is trip_summary (may need payment receipt)
- missing business purpose or attendees (if required)
- category mapping needed for policy rules
- currency conversion required for summary totals
