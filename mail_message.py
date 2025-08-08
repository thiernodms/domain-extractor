import imaplib, time
from modules.utils import logger
from .mail_analyzer import MailAnalyzer

class MailMessage:
    def __init__(self, connection, email_uid, reconnect_cb):
        self.__connection = connection
        self.__uid = email_uid  # UID (bytes)
        self.__mail_text = None
        self.__reconnect = reconnect_cb

    def process(self):
        self.__mark_as_seen()     # si tu veux avant fetch
        self.__fetch()
        if self.__mail_text:
            processor = MailAnalyzer(self.__uid, self.__mail_text)
            processor.process()
        self.__mark_as_deleted()

    def __retry_imap(self, fn, *args, **kwargs):
        for attempt in range(RETRY):
            try:
                typ, data = fn(*args, **kwargs)
                if typ == 'OK':
                    return data
                raise imaplib.IMAP4.error(f"IMAP NOT OK: {typ}")
            except imaplib.IMAP4.abort:
                # session cassée -> reconnect + retry
                self.__reconnect()
            except Exception as e:
                if attempt == RETRY - 1:
                    raise
                time.sleep(BACKOFF_BASE ** attempt)

    def __mark_as_seen(self):
        try:
            self.__retry_imap(self.__connection.uid, 'store', self.__uid, '+FLAGS', r'(\Seen)')
        except Exception as e:
            logger.error(f"Erreur marquage \\Seen UID {self.__uid}: {e}")

    def __fetch(self):
        try:
            data = self.__retry_imap(self.__connection.uid, 'fetch', self.__uid, '(RFC822)')
            if data and data[0] and isinstance(data[0], tuple):
                self.__mail_text = data[0][1]
        except Exception as e:
            logger.error(f"Erreur fetch UID {self.__uid}: {e}")
            self.__mail_text = None

    def __mark_as_deleted(self):
        try:
            self.__retry_imap(self.__connection.uid, 'store', self.__uid, '+FLAGS', r'(\Deleted)')
        except Exception as e:
            logger.error(f"Erreur marquage \\Deleted UID {self.__uid}: {e}")
