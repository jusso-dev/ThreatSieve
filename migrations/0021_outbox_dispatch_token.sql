-- Publishers must not scan historical deliveries when acknowledging or releasing a reservation.
CREATE INDEX outbox_dispatch_token ON outbox(dispatch_token,queue) WHERE dispatch_token IS NOT NULL;
