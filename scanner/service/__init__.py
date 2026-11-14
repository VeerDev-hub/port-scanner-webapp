"""
Service and version detection.

Our own small equivalent of nmap-service-probes: send a protocol-appropriate
probe, then match the response against a table of regex signatures to name the
product and pull out a version. No external service or database is contacted.
"""
