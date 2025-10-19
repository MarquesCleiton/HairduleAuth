import bcrypt


def hash_password(password: str) -> str:
    """
    Gera o hash da senha com bcrypt.
    Usado apenas na criação de usuários.
    """
    if not password:
        raise ValueError("Senha vazia")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Compara a senha em texto puro com o hash armazenado.
    """
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False
