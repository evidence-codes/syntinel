def apply_discount(total: float, discount_percent: float) -> float:
    # VULNERABLE: no bounds check — a negative or >100 discount_percent breaks pricing.
    return total - (total * discount_percent / 100)
