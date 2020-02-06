from models import *
from database import db_session
from helpers import get_config
from pathlib import Path
from config_manager import config_manager

class FileType:
    def __init__(self, read_source):
        self.read_source = read_source

    def run(self):
        print("Deletando entradas com path de arquivo nulo")
        db_session.query(File).filter(File.extracted_path == None, File.message_id ==
                          None, File.read_source_id == self.read_source.id).delete()
        print("Atribuindo tipo aos arquivos")
        files = db_session.query(File).filter_by(read_source_id=self.read_source.id).all()
        for file_ in files:
            if file_.extracted_path:

                ext = Path(file_.extracted_path).suffix
                extensions = config_manager.file_types
                if ext.lower() in extensions['image']:
                    file_.type_ = 'image'
                elif ext.lower() in extensions['video']:
                    file_.type_ = 'video'
                elif ext.lower() in extensions['audio']:
                    file_.type_ = 'audio'
                elif file_.content_type and 'image' in file_.content_type:
                    file_.type_ = 'image'
                elif file_.content_type and 'video' in file_.content_type:
                    file_.type_ = 'video'
                elif file_.content_type and 'audio' in file_.content_type:
                    file_.type_ = 'audio'
                else:
                    file_.type_ = 'file'
                message = file_.message
                if message and file_.type_ not in message.analise_attachment_types:
                    message.analise_attachment_types += "/" + file_.type_
                    db_session.add(message)
            db_session.add(file_)
        db_session.query(File).filter_by(size=0).delete()
        db_session.commit()