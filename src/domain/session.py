class Session:
    def __init__(self, session_id, user_id, expires_at):
        self.session_id = session_id
        self.user_id = user_id
        self.expires_at = expires_at
