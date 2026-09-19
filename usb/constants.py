"""Senser v2 credentials recovered from the complete dump6.bin snapshot.

A/B/C public keys and IDs were recovered from freed-memory JSON residues.
Their level fields and exact lengths agree with the corresponding filesystem
metadata; current live-camera use has not been verified. No matching private
key was recovered. The public PEMs below cannot generate signatures.
"""

# Internal camera levels: A=3, B=2, C=1. These are NOT the key IDs below.
# The supplied Out01 requests ASCII C. Keep HOP aligned with that capture.
senserAuthLevel = 'C'

# User-selected capture replay: STEP from Out02, JUMP from Out03. No private
# key is loaded in this mode. A captured signature is not proof of live auth.
# Use 'rsa' to restore signing with a matching private_key_file below.
senserAuthMode = 'capture'
senserAuthCaptureFrames = {
 'step': {
  'file': 'Auth7M5SonyUSBOut02.bin',
  # Source is 537 bytes. Use one 516-byte protocol frame explicitly; the
  # remaining 21 bytes have unknown framing and are preserved in the file.
  'offset': 0,
  'size': 516,
  'sha256': '54339e87c4a3733ab6b8c44d04aa2ba14eb6af69e027bcfd1c68a0db7ff90e00',
 },
 'jump': {
  'file': 'Auth7M5SonyUSBOut03.bin',
  # Source is 536 bytes, with 20 bytes outside the selected protocol frame.
  'offset': 0,
  'size': 516,
  'sha256': 'e06c3c4bb79ea635152d6cea4adb72f3df00838e53ea6ef2e97c8888e5db3cd2',
 },
}

# In 'rsa' mode, set private_key_file to your matching private PEM, for example
# r'C:\keys\senser_A_private.pem'. It is checked against public_key_pem
# before authentication packets are sent. Leave unknown credentials as None.
# Encrypted PEM passphrases: authenticate(mode='rsa', passphrase=...).
senserAuthKeys = {
 'A': {
  'key_id': 1,
  'private_key_file': None,
  'public_key_pem': (
   '-----BEGIN PUBLIC KEY-----\n'
   'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr6ImaGB+KAMAq+z/mxtl\n'
   '7qp3fAGdwaEXSEeDmZsIQ927qZD/L6xitL/VUXtA63XXGCZVq8li1gjiNC4tVBdP\n'
   'KWfMhjlP57th4t9LwOZvf7ingCb9BTonUYLlG3SnkRm6I7UcQ0+LEZmfDkLrVcLY\n'
   'UihaMbss6Lc6S9mzM9HFfQY20q1yfPe0XPm9nr6/Tnb7Zr+2r3piaSdXlh7VUUjr\n'
   'uDj26tDi0+5ihYxb7tKnnrvS/MDfpBvXFOlpFkJ26xREcjTZdi1JeienLTbKSMDs\n'
   'CmE4FyOY6mG02sHYv1uI7E22FMsQRV/+0Oso4i6urB+gNLCfX3VDmOkpaHwHgvun\n'
   'T2CdsFNcNQdv9b3Xj6XVyPfnoF9NPZC751r2glKGImeXAVOGouAV5pt1hfQ3u2YK\n'
   'M5KYUfNwfZ4l1GcOqN5MMmEIKqPTHbIhL/jp5YOq+ne3KQRB0uQqagwya0IskPXa\n'
   'xOESnSdLfTIwCODrN9X2wjBnIqrWnmJCptz4+XPcjLm3CxAcUyt6ZIJY7c/NChGD\n'
   'O89VuCJeFyjyLa2brd94VBRVBVonKEnlDyejj7G0ttTQBeZRdZg0tDNqrOvGLsHd\n'
   'WbF8ImzzCufUvVEzfvMx+F7Spo3r1U3hmSe/zvDf1TdVniadAlvRkym6qAH/uODi\n'
   'SA32GkrI4Mu//cUx1xVseq0CAwEAAQ==\n'
   '-----END PUBLIC KEY-----\n'
  ),
 },
 'B': {
  'key_id': 2,
  'private_key_file': None,
  'public_key_pem': (
   '-----BEGIN PUBLIC KEY-----\n'
   'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuge5SnOmTOuwACGKdNpZ\n'
   'tCa/+ocx1KoOw0Hk+fL+d2d5VncTKht9RuFFZtM4VZGvqgxSw+ynLysr4QSR60+m\n'
   'QJx/lmaaJoHj/Za5b8U+e+d48QZXwhPMqzy+bu30sctfmpdqSVIamjyBRb8UbmGu\n'
   'OdGdkRILsI+/Jbu3reR0cA6g3OB3U7y+6mMyEuElYL5z0diQzMT0k568GEJAC3AG\n'
   'N1aZxVTgyzAEWF9fSUSax1GG4MWFj4dRlSkFNcUrFWpdbhjcLZXd14WGbL/Jrai2\n'
   'iM9nRRJq/lAdNHLe+LsIhQs+Rn3ex4x50jsG3zk3o7Y+JdxFLa/vUGG7B9uuoX6G\n'
   'ZQum+JnH4O5n4rfec+n/mzph3PSBE1WtOmfDQb+N3w7kgdHifJr42L7T0NpusDx8\n'
   'F7CeNYn9xVGgxitasW01IjIMSLW+sErG0UrbLEab236aS57hrht2oDkK+rppbmls\n'
   '2pnl1eX6LqP3+VhqBZjoYzpRaCe+ANW/wnqXyDUJosc4SIYRZAthLbN36TzYYqrZ\n'
   '/yaRugsDNNVDz/AiOIs2QNczm0mcaM5OgynpgPyUrfSE77YgKjHaSUiziYJqWKMt\n'
   'OaSg1M1BqrvouNpBLPdUa5zwu+kkXIgqRRm9xIlxsLqDPJ026aghmdEnQ6dS9Har\n'
   'rNUoquSkmBzZsu2nxwNqV6sCAwEAAQ==\n'
   '-----END PUBLIC KEY-----\n'
  ),
 },
 'C': {
  'key_id': 3,
  'private_key_file': None,
  'public_key_pem': (
   '-----BEGIN PUBLIC KEY-----\n'
   'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx4ceqmV08RKcSgWhor6s\n'
   'ykZ6jN5RSuf9hwZIKWCfhKzqunh1hGfEZDbbZGF6sPrXGEu06251m2ux4TPEGVzT\n'
   'bQxDOEbPmqR/xAp3OATSg1lTSs2jBnbfX0nYJUqHHi5BcWC8yqxtxqJ/o7lkq0Ul\n'
   'yHkJByQ2/f8t14zcOkC+thrt1LTuoamqVDjy3IrvA7gcPehixrVD0CSTUiFJsSXC\n'
   'govvNkjPXDHc3jje8201dCDGx2NG6KxxwV5W7/f0QBTI80PCNu7LJnq3kd64sofu\n'
   'EilryfsbeRePsnuSQl8Un2LsX0If7T+raxMM0I1C0GjVnxXacRtEB1NzVrqhruEl\n'
   'ZEK9rm2SJLUxoF8cakMYhlGPHnSbf3YfZnJ/bV7DmZSZtmANFVcNF2kk2CNTN7fP\n'
   'x3ssnbOJN7k7hziKL2DGp2cj2kUaAvYwe3YRH4mYAD5+Lb3FhTGAjqPGLRurb57G\n'
   '2Jbhb28Gkt145LDUQ3Mo0ANNjzmkiu6KhGHj/Dqqz8l6xWbzkRRggbX8ePcAv2Q1\n'
   'Uxq+FyzoXbp5691Xz3P6eO9S+fOb9fEUwk/djmNKfpA0eOCm1lG8zz5b6jFel1eG\n'
   'LZRM69PtZr4nYzA4V/DE6OqFMTKXpbuFr+a7KpO3/LFMX0XtopyhKDFrCRgN/JaB\n'
   'a3090yREhZFyrKQypyNl+F0CAwEAAQ==\n'
   '-----END PUBLIC KEY-----\n'
  ),
 },
}

senserPublicKeyPaths = {
 'A': '/usr/share/data/key_A_public.json',
 'B': '/usr/share/data/key_B_public.json',
 'C': '/usr/share/data/key_C_public.json',
}
