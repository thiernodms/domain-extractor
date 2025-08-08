import imaplib, socket, time, itertools
from modules.dto.exceptions import ConfigException
from modules.utils import logger

RETRY = 3
BACKOFF_BASE = 1.5

def _chunks(seq, n):
    it = iter(seq)
    while True:
        batch = list(itertools.islice(it, n))
        if not batch:
            return
        yield batch

class IMAPClient:
    def __init__(self, host, port, user, password):
        self.__host = host
        self.__port = int(port)
        self.__user = user
        self.__password = password
        self.__connection = None

    def connect(self):
        socket.setdefaulttimeout(60)  # évite les sockets pendantes
        if self.__port == 143:
            self.__connection = imaplib.IMAP4(self.__host, self.__port)
        elif self.__port == 993:
            self.__connection = imaplib.IMAP4_SSL(self.__host, self.__port)
        else:
            raise ConfigException(f"Port IMAP non reconnu ({self.__port}).")
        self.__connection.login(self.__user, self.__password)
        self.__connection.select()  # INBOX

    def _reconnect(self):
        logger.warning("Reconnexion IMAP…")
        try:
            if self.__connection is not None:
                try:
                    self.__connection.logout()
                except Exception:
                    pass
        finally:
            self.connect()

    def _noop_safe(self):
        try:
            self.__connection.noop()
        except imaplib.IMAP4.abort:
            self._reconnect()

    def _fetch_unseen_uids(self, limit=None):
        # Utilise UID pour la suite (plus fiable)
        typ, data = self.__connection.uid('search', None, 'UNSEEN')
        if typ != 'OK' or not data or not data[0]:
            return []
        uids = data[0].split()
        if limit:
            uids = uids[:limit]
        return uids

    def process_emails(self, limit=500, batch_size=100, keepalive_every=50, reset_every=1500):
        uids = self._fetch_unseen_uids(limit=limit)
        processed = 0
        for batch in _chunks(uids, batch_size):
            for i, uid in enumerate(batch, 1):
                try:
                    email = MailMessage(self.__connection, uid, self._reconnect)
                    email.process()
                except imaplib.IMAP4.abort:
                    # reconnexion et retry une fois
                    self._reconnect()
                    try:
                        email = MailMessage(self.__connection, uid, self._reconnect)
                        email.process()
                    except Exception as e:
                        logger.error(f"Echec définitif sur UID {uid}: {e}")
                except Exception as e:
                    logger.error(f"Erreur traitement UID {uid}: {e}")
                processed += 1

                if processed % keepalive_every == 0:
                    self._noop_safe()
                if processed % reset_every == 0:
                    # certains serveurs aiment les sessions courtes
                    self._reconnect()
