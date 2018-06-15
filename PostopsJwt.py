import jwt

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 20

def get_token(userid, expire, flags):
  payload = {
      'id': userid,
      'expire': expire, # datetime.utcnow(),
      'flags': flags
  }
  token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
  return str(token)[2:-1]

def get_token_payload(token):
  if token is None:
    return None
  try:
    payload = jwt.decode(token[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
    return payload
  except (jwt.DecodeError, jwt.ExpiredSignatureError):
    return None # json_response({'message': 'Token is invalid'}, status=400)

