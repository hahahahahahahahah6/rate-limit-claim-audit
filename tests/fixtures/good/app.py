limiter = Limiter()
@limiter.limit("100/minute")
def route(): pass
