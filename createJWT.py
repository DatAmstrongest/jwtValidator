from datetime import datetime, timezone
import jwt

def getHeader():
    alg = input("Enter the algorithm: ") or "RS256"
    typ = input("Enter the type of token: ") or "JWT"
    x5u = input("Enter the url of the certificate server: ") or "http://localhost/api/mock/certs"
    return alg, typ, x5u

def getPayload():
    sub = input("Enter the subject (Default: 1234567890): ").strip() or "1234567890"
    name = input("Enter the name (Default: John Doe): ").strip() or "John Doe"

    current_iat = int(datetime.now(timezone.utc).timestamp())
    current_exp = current_iat + 3600  # Default: 1 hour later

    user_iat = input(f"Enter the issue time (Current time: {current_iat}): ").strip()
    user_exp = input(f"Enter the expiration time (Default: {current_exp}): ").strip()

    # Use defaults if empty; cast to int if numeric; keep as string otherwise for test cases
    if not user_iat:
        iat = current_iat
    else:
        iat = int(user_iat) if user_iat.isnumeric() else user_iat

    if not user_exp:
        exp = current_exp
    else:
        exp = int(user_exp) if user_exp.isnumeric() else user_exp

    return sub, name, iat, exp

if __name__ == "__main__":
    ### 1. Getting the inputs for the token
    alg, typ, x5u = getHeader()
    sub, name, iat, exp = getPayload()

    ### 2. Read the private key
    with open("./src/main/resources/certs/mock-key.pem") as file:
        private_key = file.read()

    ### 3. Define Header
    ### PyJWT automatically includes 'alg': 'RS256'
    custom_header = {
        "typ": typ,
        "x5u": x5u
    }

    ### 4. Define Payload
    payload = {
        "sub": sub,
        "name": name,
        "iat": iat,
        "exp": exp
    }

    ### 5. Generate the Token
    token = jwt.encode(
        payload=payload,
        key=private_key,
        algorithm=alg,
        headers=custom_header
    )

    ### 6. Print the resulting token
    print("\nGenerated Token:")
    print(token)








