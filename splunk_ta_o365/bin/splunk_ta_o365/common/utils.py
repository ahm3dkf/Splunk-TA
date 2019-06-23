from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import tzutc


_EPOCH = datetime(1970, 1, 1, 0, 0, 0, 0, tzinfo=tzutc())


def string_to_timestamp(text):
    dt = parse(text)
    elapse = dt - _EPOCH
    return elapse.total_seconds()
