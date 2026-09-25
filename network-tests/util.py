import random


def random_time_delta_ms(upper: int) -> int:
    return random.randint(1, upper * 1000)
