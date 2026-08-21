# VULNERABLE: hardcoded credential committed to source.
# NOTE: deliberately NOT a well-formed Stripe key — this is a scanner fixture,
# not a real secret, and must not match GitHub push-protection patterns.
STRIPE_SECRET_KEY = "REPLACE_ME-hardcoded-payment-api-key-do-not-ship-this"
