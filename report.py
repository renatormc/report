import click
import helpers_cmd as hp
import os
import sys
import shutil
import settings
import parsers
from processors import processor_factory, get_list_processors
from models import *
import models
from database import db_session
from database import db_connect
from helpers import get_items_available
from config_manager import config_manager
from report_maker import ReportMaker
from sinf.exe_finder import open_in_browser
from subprocess import Popen, CREATE_NEW_CONSOLE
from PyInquirer import style_from_dict, Token, prompt, Separator
from processors.proprietary_finder import ProprietaryFinder
from time import sleep
from datetime import datetime
import importlib
import helpers_dblocal as hp_db
import multiprocessing
from contextlib import contextmanager
from multiprocessing import Pool    
import constants
from termcolor import cprint
import colorama
from word_handler import WordHandler

colorama.init()


@contextmanager
def poolcontext(*args, **kwargs):
    pool = multiprocessing.Pool(*args, **kwargs)
    yield pool
    pool.terminate()



def process_avatars():
    read_sources = db_session.query(ReadSource).all()
    for read_source in read_sources:
        p = processor_factory('ProcessAvatars', read_source)
        p.run()


@click.group()
# @click.option('--debug/--no-debug', default=False)
@click.pass_context
def cli(ctx):
    pass
    # ctx.obj['DEBUG'] = debug


@cli.command()
@click.option('--grouped/--no-grouped', default=False)
@click.option('--dbtype', type=click.Choice(['sqlite', 'mysql', 'postgres']), default='mysql')
def init(grouped, dbtype):
    hp.askfor_update()
    if os.path.exists(".report"):
        hp.instruct_continue(
            "Já existe um projeto em andamento nessa pasta. Deseja reiniciá-lo? Isso implicará a perda de tudo que foi feito até agora.")
    errors = hp.check_folder_structure()
    if errors:
        print("\nSua estrutura de pastas parece não atender aos critérios necessários. Leia o tutorial no SINFWeb.")
        print("\nPossíveis erros encontrados: ")
        # print("\nPossíveis erros encontrados:")
        for error in errors:
            cprint(f" -> {error}", "yellow")
            # print(error)
        print("\n")
        hp.show_options_cancel("O que deseja fazer?", [
                               'Continuar mesmo assim. Os erros detectados são falsos.'], cancel_option=True)
        # hp.instruct_continue("")

    hp.reset(dbtype=dbtype)
    sleep(1)
    os.mkdir('.report')
    os.system("attrib +h " + ".report")
    shutil.copytree(settings.app_dir / "scripts", ".report\\scripts")
    hp.set_working_dir_scripts()
    shutil.copytree(settings.app_dir / "notebooks", ".report\\notebooks")
    shutil.copy(settings.app_dir / "reader/static/image/desconhecido.png",
                ".report\\desconhecido.png")
    hp.set_working_dir_notebooks()
    shutil.copytree(settings.app_dir / "config_files/config",
                    Path(".report/config"))
    config_manager.set_grouped(grouped)

    from database import init_db
    print(f"Gerando banco de dados {dbtype}")
    if dbtype != 'sqlite':
        hp_db.create_database_localdb(type=dbtype)
        hp_db.drop_orphan_databases(type=dbtype, exclude=[config_manager.database_name])
        n_cpu = multiprocessing.cpu_count()
        config_manager.data['n_workers'] = n_cpu if n_cpu <= 8 else 8
        config_manager.save()
       
    config_manager.load_database_name()
    db_connect()
    importlib.reload(models)
    init_db()
    hp.copy_config_files(overwrite=True)
    shutil.copy(settings.app_dir / "go/starter_normal.exe",
                constants.ANALYZER_EXE_NAME)
    print("\nAmbiente preparado. Antes de processar não se esqueça de editar os arquivos \"config_source.yaml\" que se encontram dentro de cada pasta de fonte de dados.")


@cli.command()
def process():
    start_time = datetime.now()

    #atualizar arquivos yaml
    hp.update_sources()
    read_sources = db_session.query(ReadSource).filter(ReadSource.process == True).all()
    # for read_source in read_sources:
    #     if read_source.source_type == 'xml_ufed':
    #         config_manager.set_data_file(read_source.folder)

    hp.update_sources()
    read_sources = db_session.query(ReadSource).filter(ReadSource.process == True).all()
    for read_source in read_sources:
        print(f"Iniciando processamento {read_source.folder}")
        parser = parsers.parsers_dict[read_source.source_type]()
        parser.set_read_source(read_source)
        msgs = parser.check_env()
        if msgs:
            for msg in msgs:
                print(msg)
            sys.exit()
        hp.clear_read_source(read_source)
        parser.run()
        del parser
        for item in config_manager.data['processors']:
            processor = processor_factory(item, read_source)
            processor.run()
        config_manager.set_process(read_source.folder, False)
        read_source.process = False
        db_session.add(read_source)
        db_session.commit()
    delta = datetime.now() - start_time
    print(f"\nProcessamento finalizado. Tempo gasto: {delta}")


@cli.command()
def render():
    op = hp.show_options_cancel("Configurações do relatório:", options=[
                                'Utilizar configurações padrão', 'Editar arquivo de configurações antes de continuar'])
    if op == 'Editar arquivo de configurações antes de continuar':
        hp.open_report_config()
        hp.instruct_continue("")
        config_manager.load_report_config()
    hp.delete_reports()
    if config_manager.report_config['folder'] == 'device':
        devices = db_session.query(Device).all()
        for device in devices:
            report_maker = ReportMaker()
            report_maker.set_item_source(device)
            report_maker.generate_html_files()
    if config_manager.report_config['folder'] == 'read_source':
        read_sources = db_session.query(ReadSource).all()
        for rs in read_sources:
            report_maker = ReportMaker()
            report_maker.set_item_source(rs)
            report_maker.generate_html_files()
    

@cli.command()
def update():
    hp.copy_config_files()
    hp.update_sources()
    process_avatars()
    

# @cli.command()
# def portable():
#     if os.path.exists(".report\\gui_server"):
#         shutil.rmtree(".report\\gui_server")
#     hp.copy_folder(settings.app_dir / "reader/dist/gui_server",
#                    ".report\\gui_server")
#     shutil.copy(settings.app_dir / "go/starter_portable.exe",
#                 constants.ANALYZER_PORTABLE_EXE_NAME)
#     if config_manager.is_localdb():
#         print(
#             f"Migrando banco de dados de {config_manager.database_type} para sqlite.")
#         path = Path(".report/db.db")
#         if path.exists():
#             path.unlink()
#         from local2sqlite.migrate import run_migrate
#         run_migrate()


# @cli.command()
# def dbb():
#     os.system("s-dbb .report\\db.db")


@cli.command()
def db_config():
    path = Path(f"{settings.sinftools_dir}/var/sinf_report_db.json")
    if not path.exists():
        if not path.exists():
            shutil.copy(Path(settings.app_dir / "dev/sinf_report_db.json"), path)
    os.system(f's-np "{path}"')

@cli.command()
def list_dbs():
    dbs = hp_db.get_db_list()
    type_ = config_manager.database_type
    for db in dbs:
        print("-----------------------------------------")
        print(f"NOME: {db[0]}\nPASTA: {db[1]}\nTIPO: {type_}")


@cli.command()
@click.option('--dbtype', type=click.Choice(['mysql', 'postgres']), default='mysql')
def dropdb(dbtype):
    hp_db.drop_orphan_databases(type=dbtype)
    

@cli.command()
@click.option('--edit/--no-edit', default=False)
@click.option('--search', default="")
def script(edit, search):
    scripts = os.listdir(".report\\scripts")
    if search != "":
        scripts = list(filter(lambda x: search in x, scripts))

    if scripts:
        questions = [
            {
                'type': 'list',
                'message': "Selecione o script",
                'name': 'script',
                'pageSize': 3,
                'choices': scripts
            }
        ]
        script = prompt(questions, style=hp.style)['script']
        if edit:
            Popen(
                f"\"{settings.sinftools_dir}\\Miniconda3\\pythonw.exe\" \"{settings.sinftools_dir}\\Miniconda3\\Scripts\\idlex.pyw\" .report\\scripts\\{script}")
        else:
            os.system(
                f"\"{settings.sinftools_dir}\\Miniconda3\\python.exe\" .report\\scripts\\{script}")
    else:
        print("Nenhum script com este nome foi encontrado")


@cli.command(help="Generates command to be used inside Physical Analyzer to export avatars.")
@click.option('--phone-type', type=click.Choice(['android', 'iphone']), default="android")
def avatar(phone_type):
    folder = Path(hp.choose_read_source())
    print("Abra o shell de scripts python dentro do Physical Analyzer, e execute o comando abaixo: \n")
    if phone_type == 'android':
        cmd = f"execfile(r'{settings.sinftools_dir}\\tools\\ufed\\ufed.py');ufed.exportar_avatars(r'{folder.absolute()}')"
        print(cmd)
    elif phone_type == 'iphone':
        cmd = f"execfile(r'{settings.sinftools_dir}\\tools\\ufed\\ufed.py');ufed.exportar_avatars_iphone(r'{folder.absolute()}')"
        print(cmd)


@cli.command(help="Open analyzer")
@click.option('--new-window/--no-new-window', default=False)
@click.option('--mode', default="waitress")
def analyzer(mode, new_window):
    os.environ['exec_mode'] = mode
    path = settings.reader_folder / "server.py"
    if new_window:
        Popen(f"cmd /k s-py {path} {mode}",
            creationflags=CREATE_NEW_CONSOLE)
    else:
        python = settings.sinftools_dir / "Miniconda3/python"
        Popen(f'"{python}" "{path}" {mode}')


@cli.command()
@click.option('--processors', default="list")
def extra_process(processors):
    if processors == 'list':
        print("Utilize s-report extra_process --processors Processor1,Processor2,...\n")
        for p in get_list_processors():
            print(p)
    else:
        start_time = datetime.now()
        processors = processors.split(",")
        read_sources = db_session.query(ReadSource).all()
        for p in processors:
            for rs in read_sources:
                processor = processor_factory(p, rs)
                processor.run()
        delta = datetime.now() - start_time
        print(f"Processamento finalizado. Tempo gasto: {delta}")


@cli.command()
@click.option('--name')
@click.option('--username')
@click.option('--password')
def create_user(name, username, password):
    user = db_session.query(User).filter_by(username=username).first()
    if not user:
        user = User()
    user.username = username
    user.name = name
    user.set_password(password)
    db_session.add(user)
    db_session.commit()
    print("Usuário criado.")

@cli.command()
@click.option('--tags', required=True, help="Only items checked with tags especified here will be included. If more than one put them separated by comma.")
@click.option('--item', type=click.Choice(['image', 'video', 'chat']), required=True)
@click.option('--n_cols', type=int, default=3, help="Number of images per row at the table")
@click.option('--caption', default="Exemplo de mensagens de bate-papo")
def word(tags, item, n_cols, caption):
    tags = [item.strip() for item in tags.split(",")]
    for tag in tags:
        if not db_session.query(Tag).filter_by(name=tag).count():
            print(f'Tag "{tag}" não existe.')
            print("Escolha dentre as opções: \n")
            for item in db_session.query(Tag.name).all():
                print(item[0])
            return 
    wh = WordHandler()
    if item == 'image':
        files = db_session.query(File).filter(File.type_ == 'image', File.tags.any(Tag.name.in_(tags))).all()
       
        if not files:
            print(f"Nenhuma imagem marcada com as tags {tags}")
            return
        files = [file_.path for file_ in files]
        wh.insert_images(n_cols, files)
    elif item == 'video':
        files = db_session.query(File).filter(File.type_ == 'video', File.tags.any(Tag.name.in_(tags))).all()
        if not files:
            print(f"Nenhum video marcado com as tags {tags}")
            return
        files = [file_.thumb_path for file_ in files]
        wh.insert_images(n_cols, files)
    elif item == 'chat':
        messages = db_session.query(Message).filter(Message.tags.any(Tag.name.in_(tags))).all()
        wh.insert_chat_messages_table(caption, messages)



@cli.command()
def list_users():
    users = db_session.query(User).all()
    for user in users:
        print(user.username)


@cli.command(help="Mark all read sources to process.")
def mark_all_to_process():
    for rs in db_session.query(ReadSource).all():
        config_manager.set_process(rs.folder, True)
		
@cli.command()
def gen_yaml():
    p = Path('config_source.yaml')
    if not p.exists():
        shutil.copy(settings.app_dir /
                "config_files/config_source.yaml", p)

@cli.command()
def db_name():
    database_name = config_manager.database_name
    if database_name:
        print(database_name)
        

if __name__ == '__main__':
    cli(obj={})
