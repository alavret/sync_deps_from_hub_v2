import os
from dotenv import load_dotenv
from datetime import datetime
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, Tls, MODIFY_REPLACE, set_config_parameter, utils
from ldap3.core.exceptions import LDAPBindError
import logging
import logging.handlers as handlers
import sys
import requests
from dataclasses import dataclass
from http import HTTPStatus
import time

LOG_FILE = "sync_deps.log"
EMAIL_DOMAIN = "domain.ru"
DEFAULT_360_API_URL = "https://api360.yandex.net"
ITEMS_PER_PAGE = 100
MAX_RETRIES = 3
RETRIES_DELAY_SEC = 2
SLEEP_TIME_BETWEEN_API_CALLS = 0.5
ALL_USERS_REFRESH_IN_MINUTES = 15
USERS_PER_PAGE_FROM_API = 1000
DEPARTMENTS_PER_PAGE_FROM_API = 100
SENSITIVE_FIELDS = ['password', 'oauth_token', 'access_token', 'token']
EXIT_CODE = 1

logger = logging.getLogger("sync_deps")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
#file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30, encoding='utf-8')
file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024,  backupCount=20, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def build_group_hierarchy(settings: "SettingParams"):

    set_config_parameter('DEFAULT_SERVER_ENCODING', 'utf-8')
    set_config_parameter('ADDITIONAL_SERVER_ENCODINGS', 'koi8-r')

    #attrib_list = list(os.environ.get('ATTRIB_LIST').split(','))
    attrib_list = ['*', '+']

    server = Server(settings.ldap_host, port=settings.ldap_port, get_info=ALL) 
    try:
        logger.debug(f'Trying to connect to LDAP server {settings.ldap_host}:{settings.ldap_port}')
        conn = Connection(server, user=settings.ldap_user, password=settings.ldap_password, auto_bind=True)
    except LDAPBindError as e:
        logger.error('Can not connect to LDAP - "automatic bind not successful - invalidCredentials". Exit.')
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    logger.info(f'Connected to LDAP server {settings.ldap_host}:{settings.ldap_port}')

    users = []
    logger.info(f'Trying to search users. LDAP filter: {settings.ldap_search_filter}')
    conn.search(settings.ldap_base_dn, settings.ldap_search_filter, search_scope=SUBTREE, attributes=attrib_list)
    if conn.last_error is not None:
        logger.error('Can not connect to LDAP. Exit.')
        #logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return {}
    logger.info(f'Found {len(conn.entries)} records.')
    try:            
        for item in conn.entries:
            entry = {}
            if item['objectCategory'].value.startswith('CN=Person'):
                if len(item.entry_attributes_as_dict.get('mail','')) > 0:
                    ex14 = ''
                    if len(item.entry_attributes_as_dict.get('extensionAttribute14','')) > 0:
                        ex14 = item.entry_attributes_as_dict.get('extensionAttribute14','')[0].lower().strip()
                    entry['mail'] = item['mail'].value.lower().strip().replace("[","").replace("]","").replace("'","")                       
                    entry['extensionAttribute14'] = ex14
                    if item['displayName'].value is not None:
                        entry['displayName'] = item['displayName'].value.lower().strip()
                    else:
                        entry['displayName'] = item['cn'].value.lower().strip() 

                    users.append(entry)

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return {}
    logger.info('All users are processed.')
    
    hierarchy = []
    all_dn = []
    root_group_search_filter = f"(distinguishedName={settings.hab_root_group})"
    logger.info(f'Trying to search root group. LDAP filter: {root_group_search_filter}')
    conn.search(settings.ldap_base_dn, root_group_search_filter, search_scope=SUBTREE, attributes=attrib_list)
    if conn.last_error is not None:
        logger.error('Can not connect to LDAP. Exit.')
        #logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    if len(conn.entries) == 0:
        logger.error('Can find root group. Exit.')
        return []
    
    item = conn.entries[0]
    if len(item.entry_attributes_as_dict.get('displayName','')) > 0:
        name = conn.entries[0]['displayName'].value
    else:
        name = conn.entries[0]['cn'].value

    raw_mail = item.entry_attributes_as_dict.get('mail','')
    if isinstance(raw_mail, list):
        group_mail = raw_mail[0].lower().strip()
    else:
        group_mail = raw_mail.lower().strip()
    logger.info(f'Root group name: {name}, group mail: {group_mail}')
    hierarchy.append(f"{name}~{group_mail}")
    root_group_name = name
    logger.info(f'Add users to group {name}')
    count_users = 0
    if len(item.entry_attributes_as_dict.get('sAMAccountName','')) > 0:
        sam_name = conn.entries[0]['sAMAccountName'].value.lower().strip()
        for user in users:
            if len(user["extensionAttribute14"]) > 0:
                if user["extensionAttribute14"] == sam_name:
                    count_users += 1
                    hierarchy.append(f"{root_group_name}|{user['displayName']};{user['mail']}")
    logger.info(f'Added {count_users} users to group {name}.')
    hierarchy, all_dn = build_hierarcy_recursive(conn, settings, attrib_list, root_group_name, conn.entries[0], hierarchy, all_dn, users)
    logger.info('AD data has been generated.')
    if settings.ad_data_file:
        with open(settings.ad_data_file, "w", encoding="utf-8") as f:
            for line in hierarchy:
                f.write(f"{line}\n")
        logger.info(f'AD data has been saved to file {settings.ad_data_file} ({len(hierarchy)} lines).')
    return hierarchy, all_dn

def build_hierarcy_recursive(conn, settings: "SettingParams", attrib_list, base, item, hierarchy, all_dn, users):

    ldap_search_filter = f"(memberOf={utils.conv.escape_filter_chars(item['distinguishedName'].value)})"
    logger.info(f'Trying to search members of group. LDAP filter: {ldap_search_filter}')
    conn.search(settings.ldap_base_dn, ldap_search_filter, search_scope=SUBTREE, attributes=attrib_list)
    logger.info(f'Found {len(conn.entries)} records.')
    try:            
        for item in conn.entries:            
            if item['objectCategory'].value.startswith("CN=Group"):
                all_dn.append(item['distinguishedName'].value)
                sam_name = item['sAMAccountName'].value.lower().strip()
                raw_mail = item.entry_attributes_as_dict.get('mail','')
                if isinstance(raw_mail, list):
                    group_mail = raw_mail[0].lower().strip()
                else:
                    group_mail = raw_mail.lower().strip()
                 
                #group_mail = f"{item['sAMAccountName'].value}@{EMAIL_DOMAIN}"
                if len(item.entry_attributes_as_dict.get('displayName','')) > 0:
                    hierarchy.append(f"{base};{item['displayName'].value}~{group_mail}")
                    previuos = f"{base};{item['displayName'].value}"
                else:
                    hierarchy.append(f"{base};{item['cn'].value}~{group_mail}")
                    previuos = f"{base};{item['cn'].value}"
                logger.info(f"Add group {item['distinguishedName'].value} to hierarchy.")
                logger.info(f"Add users to group {item['distinguishedName'].value}")
                count_users = 0
                for user in users:
                    if len(user["extensionAttribute14"]) > 0:
                        if user["extensionAttribute14"] == sam_name:
                            count_users += 1
                            hierarchy.append(f"{previuos}|{user['displayName']};{user['mail']}")
                logger.info(f"Added {count_users} users to group {item['distinguishedName'].value}.")
                hierarchy, all_dn = build_hierarcy_recursive(conn, settings, attrib_list, previuos, item, hierarchy, all_dn, users)


    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return [],[]
   
    return hierarchy, all_dn


def generate_deps_list_from_api(settings: "SettingParams"):

    all_deps_from_api = get_all_api360_departments(settings)
    if len(all_deps_from_api) == 1:
        #print('There are no departments in organozation! Exit.')
        return []
    all_deps = []
    for item in all_deps_from_api:        
        path = item['name'].strip()
        mail = item['label'].lower()
        prevId = item['parentId']
        if prevId > 0:
            while not prevId == 1:
                d = next(i for i in all_deps_from_api if i['id'] == prevId)
                path = f"{d['name'].strip()};{path}"
                prevId = d['parentId']
            element = {'id':item['id'], 'parentId':item['parentId'], 'path':path, 'mail':mail}
            all_deps.append(element)
    return all_deps

def load_heirarchy_from_file(file_path):
    hierarchy = []
    with open(file_path, 'r', encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                hierarchy.append(line)
    return hierarchy

def check_similar_mails_in_hierarchy(hierarchy):
    # Функция проверки наличия похожих почтовых адресов в иерархии
    logger.info(f'Check similar mails in hierarchy. Source data has {len(hierarchy)} items.')
    count_disct = {}
    for item in hierarchy:
        if '|' in item:
            alias = item.split('|')[1].split(';')[1].split('@')[0]
        elif '~' in item:
            alias = item.split('~')[1].split('@')[0]
        if alias:
            if alias in count_disct.keys():
                count_disct[alias] += 1
            else:
                count_disct[alias] = 1

    bad_aliases = [k for k, v in count_disct.items() if v > 1]
    if len(bad_aliases) > 0:
        logger.error('Error! One or several AD users or groups have similar aliases. Check emails of this users or groups.')
        for alias in bad_aliases:
            for item in hierarchy:
                if '|' in item:
                    if item.split('|')[1].split(';')[1].split('@')[0] == alias:
                        logger.error(f"AD User _ {item.split('|')[1].split(';')[0]} _ with alias _ {item.split('|')[1].split(';')[1].split('@')[0]} _ in group _ {item.split('|')[0]} _.")
                elif '~' in item:
                    if item.split('~')[1].split('@')[0] == alias:
                        logger.error(f"AD Group _ {item.split('~')[0]} _ with alias _ {item.split('~')[1]} _.")
        return False
    return True 

def check_similar_groups_in_hierarchy(all_dn):
    # Функция проверки наличия похожих почтовых адресов в иерархии
    logger.info(f'Check similar groups in hierarchy. Source data has {len(all_dn)} items.')
    all_dn.sort()
    compared_item = ''
    no_errors = True
    for item in all_dn:
        if item != compared_item:
            compared_item = item
        else:
            logger.error(f'Error! HAB group {compared_item} is member of several groups.')
            no_errors = False
    return  no_errors
   

def create_dep_from_prepared_list(settings: "SettingParams", deps_list, max_levels):
    # Фнункция создания департамента из предварительно подготовленного списка
    #print('Create new departments..')
    api_prepared_list = generate_deps_list_from_api(settings)
    for i in range(0, max_levels):
        #Выбираем департаменты, которые будем добавлять на каждом шаге (зависит от уровня level)
        deps_to_add = [d for d in deps_list if d['level'] == i+1]
        need_update_deps = False
        for item in deps_to_add:         
            #Ищем в основном словаре элемент-родитель для данного департамента
            d = next((e for e in deps_list if e['path'] == item['prev']), None)
            item['prevId'] = d['360id']
            #Проверяем, что данный департамент уже добавлен в систему
            t = next((e for e in api_prepared_list if e['path'] == item['path']), None)   
            if t is None:
                department_info = {
                                "name": item['current'],
                                "parentId": d['360id'],
                            }
                if item['email']:
                    department_info['label'] = item['email'].split('@')[0]
                if not settings.dry_run:
                    result =create_department_by_api(settings, department_info)
                else:
                    logger.info(f"Dry run: department {item['current']} will be created")
                need_update_deps = True
        if need_update_deps:
            api_prepared_list = generate_deps_list_from_api(settings)
        for item in deps_to_add:
            # Ищем в списке департаментов в 360 конкретное значение
            #d = next(i for i in all_deps_from_api if i['name'] == item['current'] and i['parentId'] == item['prevId'])
            #if not dry_run:
            for target in api_prepared_list:
                if target['path'] == item['path']:
                    item['360id'] = target['id']
                    break
            #d = next(i for i in api_prepared_list if i['path'] == item['path'])
            #Обновляем информацию в final_list для записанных в 360 департаментов
    return deps_list


def prepare_deps_list_from_ad_hab(settings: "SettingParams", hierarchy):

    logger.info(f'Prepare deps list from AD hierarchy. Source data has {len(hierarchy)} items.')
    deps_list = [{'current': 'All', 'prev': 'None', 'level': 0, '360id': 1, 'prevId': 0, 'path': 'All', 'email': ''}]
    # Формируем уникальный список всей иерархии подразделений (каждое подразделение имеет отдельную строку в списке)
    for item in hierarchy:
        if '|' not in item:
            dep = item.split('~')[0].split(';')
            if item.endswith("~"):
                email = ''
            else:
                email = item.split('~')[1]
            if len(dep) == 1:
                deps_list.append({'current':dep[0], 'prev':'All', 'level':1, '360id':0, 'prevId':0, 'path':'', 'email': email})
            else:
                deps_list.append({'current':dep[-1], 'prev':';'.join(dep[:-1]), 'level':len(dep), '360id':0, 'prevId':0, 'path':'', 'email': email})
    # Фильрация уникальных значений из списка словарей, полученного на предыдущем этапе
    #final_list = [dict(t) for t in {tuple(d.items()) for d in temp_list}]
    # Заполнение поля path (полный путь к подразделению)
    for item in deps_list:
        if not item['current'] == 'All':
            if item['prev'] == 'All':
                item['path'] = item['current']
            else:
                item['path'] = f"{item['prev']};{item['current']}"

    if settings.deps_file:
        with open(settings.deps_file, "w", encoding="utf-8") as f:
            for line in deps_list:
                f.write(f"{line['current']}~{line['prev']}~{line['level']}~{line['360id']}~{line['prevId']}~{line['path']}~{line['email']}\n")
        logger.info(f'AD data has been saved to file {settings.deps_file} ({len(deps_list)} lines).')
    # Добавление в 360
    return deps_list

def delete_deps_from_y360(settings: "SettingParams", created_deps, reason):
    temp_deps_from_y360 = generate_deps_list_from_api(settings)
    deps_from_y360 = sorted(temp_deps_from_y360, key=lambda x: len(x['path'].split(';')))
    deps_from_y360.append({'id':1,'path':'All'})
    deps_to_delete = set()
    deps_to_change_name = []
    y360_users = get_all_api360_users(settings, True)
    if reason == "no_synced_from_ad":
        logger.info(f"Source data has {len(deps_from_y360)} departments in Y360. Check if there are departments which are not synced from AD.")
        for item360 in deps_from_y360:
            if item360['path'] not in [d['path'] for d in created_deps]:
                if item360['id'] != 1:
                    logger.info(f"Found department which is not synced from AD - {item360['path']}")
                    deps_to_delete.add(item360['id'])
    elif reason == "same_email":
        logger.info(f"Found {len(deps_from_y360)} departments in Y360. Check if there are departments with same emails with AD departments.")
        for item360 in deps_from_y360:
            if item360['id'] != 1:
                for itemAD in created_deps:
                    if '@' in itemAD['email']:
                        mailAD = itemAD['email'].split('@')[0]
                    else:
                        mailAD = itemAD['email']
                    if len(mailAD) > 0 and len(item360['mail']) > 0:
                        if item360['mail'] == mailAD.lower():
                            prev360 = next(item for item in deps_from_y360 if item['id'] == item360['parentId'])['path']
                            # Проверяем, что имя подразделения было изменено
                            old_name = item360['path'].split(';')[-1]
                            new_name = itemAD['path'].split(';')[-1]
                            if old_name != new_name:
                                if prev360 != itemAD['prev']:
                                    logger.info(f"Found departments with same emails {item360['mail']} but different names (old name: {old_name}, new name: {new_name}) and different parents (old parent: {prev360}, new parent: {itemAD['prev']}). Delete {item360['path']} department.")
                                    deps_to_delete.add(item360['id'])
                                else:
                                    logger.info(f"Found departments with same emails {item360['mail']} but different names (old name: {old_name}, new name: {new_name}) and same parents ({prev360}). Change name of department to {new_name}.")
                                    # Меняем имя подразделения в списке подразделений в 360
                                    for deps in deps_from_y360:
                                        temp_path = deps['path'].split(';')
                                        new_path = []
                                        if old_name in temp_path:
                                            for temp in temp_path:
                                                if temp == old_name:
                                                    new_path.append(new_name)
                                                else:
                                                    new_path.append(temp)
                                            logger.info(f" - department path has been changed from {';'.join(temp_path)} to {deps['path']}.")
                                            deps['path'] = ';'.join(new_path)
                                        
                                    deps_to_change_name.append({'id':item360['id'], 'name':itemAD['path'].split(';')[-1]})
                            break

    if len(deps_to_delete) > 0:     
        logger.info(f"Found {len(deps_to_delete)} departments to delete.")
        deleted_deps = []
        for deps_id in list(deps_to_delete):
            deps_path = next(item for item in deps_from_y360 if item['id'] == deps_id)['path']
            path_to_delete = [line for line in deps_from_y360 if line['path'].startswith(deps_path)]
            sorted_paths = sorted(path_to_delete, key=lambda x: len(x['path']), reverse=True)
            for item in sorted_paths:
                deps_id = next(dep for dep in deps_from_y360 if dep['path'] == item['path'])['id']
                if deps_id not in deleted_deps:
                    deleted_deps.append(deps_id)
                    for user in y360_users:
                        if user['departmentId'] == deps_id:
                            if not settings.dry_run:
                                logger.info(f"Try to change department of {user['email']} user from _ {deps_path} _ to _ All _")
                                patch_user_by_api(settings, user['id'], {'departmentId': 1})
                            else:
                                logger.info(f"Dry run: department of {user['email']} user will be changed from _ {deps_path} _ to _ All _")

                    if not settings.dry_run:
                        #logger.info(f"Try to delete department {deps_path} from Y360.")
                        department_info = {'id': deps_id, 'name': item['path']}
                        delete_department_by_api(settings, department_info)
                    else:
                        logger.info(f"Dry run: department {deps_path} will be deleted")

    if len(deps_to_change_name) > 0:
        logger.info(f"Found {len(deps_to_change_name)} departments to change name.")
        for item in deps_to_change_name:
            if not settings.dry_run:
                logger.info(f"Try to change name of department {item['id']} to {item['name']}")
                patch_department_by_api(settings, item['id'], {'name': item['name']})
            else:
                logger.info(f"Dry run: name of department {item['id']} will be changed to {item['name']}")

def assign_users_to_deps(settings: "SettingParams", created_deps, y360_users, ad_users):
    checked_users = []
    for user in ad_users:
        alias = user.split('|')[1].split(';')[1].split('@')[0]
        found_id = ''
        found_user_dep_id = ''
        found_user = None
        for y360_user in y360_users:
            if y360_user['nickname'].lower() == alias:
                found_id = y360_user['id']
                found_user_dep_id = y360_user['departmentId']
                found_user = y360_user
                break
        if not found_id:
            for y360_user in y360_users:
                for contact in y360_user['contacts']:
                    if contact['type'] == 'email':
                        if contact['value'].split('@')[0].lower() == alias:
                            found_id = y360_user['id']
                            found_user_dep_id = y360_user['departmentId']
                            found_user = y360_user
                if found_id:
                    break
        if found_id:
            checked_users.append(found_user)
            ad_deps_path = user.split('|')[:-1][0]
            for deps in created_deps:
                if deps['path'] == ad_deps_path:
                    if deps['360id'] != found_user_dep_id:
                        logger.info(f"User {y360_user['email']} found in Y360, but with wrong department. Change department to {deps['path']}")
                        if not settings.dry_run:
                            patch_user_by_api(settings, found_id, {'departmentId': deps['360id']})
                        else:
                            logger.info(f"Dry run: department of {user.split('|')[1].split(';')[1]} user will be changed from _ {found_user_dep_id} _ to _ {deps['path']} _")
                    break
        else:
            logger.info(f"AD User {user.split('|')[1]} not found in Y360.")

    users_dict = {}
    for user in y360_users:
        users_dict[user['id']] = user

    y360ids = set([user['id'] for user in y360_users])
    checked_ids  = set([user['id'] for user in checked_users])

    missed_ids = y360ids.difference(checked_ids)
    for id in missed_ids:
        if users_dict[id]['departmentId'] > 1:
            logger.info(f"User {users_dict[id]['email']} not found in Active Directory. Change department to _ All _")
            if not settings.dry_run:
                    patch_user_by_api(settings, id, {'departmentId': 1})
            else:
                logger.info(f"Dry run: department of user {users_dict[id]['email']} will be changed to _ All _")

def assign_users_to_deps2(settings: "SettingParams", created_deps, ad_users):
    add_to_360_aliases = []
    add_to_360 = []
    delete_candidates_from_360 = []
    delete_from_360 = []
    y360_users = get_all_api360_users(settings, True)
    logger.info(f"Assign users to departments. Found {len(created_deps)} departments in AD and {len(y360_users)} users in Y360.")
    for deps in created_deps:
        if deps['360id'] != 1:
            users_360 = [user for user in y360_users if user['departmentId'] == deps['360id']]
            emails_ad = [user.split('|')[1].split(';')[1].lower() for user in ad_users if deps['path'] == user.split('|')[0]]

            for email in emails_ad:
                if '@' in email:
                    email = email.split('@')[0]
                found_user = False
                for user in users_360:
                    aliases = [alias.lower() for alias in user['aliases']]
                    if user['nickname'].lower() == email or email in aliases:
                        found_user = True
                        break
                if not found_user:
                    add_to_360_aliases.append({"alias":email, "departmentId":deps['360id'], "path" : deps['path']})

            for user in users_360:
                found_user = False
                aliases = [alias.lower() for alias in user['aliases']]  
                for email in emails_ad:
                    if '@' in email:
                        email = email.split('@')[0]
                    if email == user['nickname'].lower() or email in aliases:
                        found_user = True
                        break
                if not found_user:
                    delete_candidates_from_360.append(user)

    for data in add_to_360_aliases:
        for user in y360_users:
            aliases = [alias.lower() for alias in user['aliases']]  
            if data['alias'].lower() == user['nickname'].lower() or data['alias'].lower() in aliases:
                add_to_360.append({"user":user, "departmentId":data['departmentId']})
                break
    
    for user in delete_candidates_from_360:
        found_user = False
        for data in add_to_360:
            if user['id'] == data['user']['id']:
                found_user = True
                break
        if not found_user:
            delete_from_360.append(user)

    if len(delete_from_360) > 0:
        logger.info(f"Found {len(delete_from_360)} users to change department to _ All _.")
    for user in delete_from_360:
        logger.info(f"Change department of user {user['email']} to _ All _")
        if not settings.dry_run:
            patch_user_by_api(settings, user['id'], {'departmentId': 1})
        else:
            logger.info(f"Dry run: department of user {user['email']} will be changed to _ All _")

    if len(add_to_360) > 0:
        logger.info(f"Found {len(add_to_360)} users to change department.")
    for user in add_to_360:
        logger.info(f"Change department of user {user['user']['email']} to {user['path']} (departmentId: {user['departmentId']})")
        if not settings.dry_run:
            patch_user_by_api(settings, user['user']['id'], {'departmentId': user['departmentId']})
        else:
            logger.info(f"Dry run: Change department of user {user['user']['email']} to {user['departmentId']}")

def delete_deps_with_no_users(settings: "SettingParams"):
    all_deps_from_api = get_all_api360_departments(settings)
    if len(all_deps_from_api) > 1:
        logger.info(f"Found {len(all_deps_from_api)} departments in Y360. Check if there are departments with no users.")
    for dep in all_deps_from_api:
        if dep['id'] != 1:
            if dep['membersCount'] == 0:
                if not settings.dry_run:
                    logger.info(f"Found department {dep['name']} with no users. Delete it.")
                    delete_department_by_api(settings, dep)
                else:
                    logger.info(f"DRY RUN: Found department {dep['name']} with no users. Delete it.")

def filter_empty_ad_deps(hierarchy):
    out_hierarchy = []
    if len(hierarchy) == 0:
        return []
    logger.info(f'Filter empty AD deps from hierarchy. Source data has {len(hierarchy)} items.')
    for item in hierarchy:
        found_users = False
        if '|' not in item:
            compare_with = item.split('~')[0]
            for line in hierarchy:
                if '|' in line:
                    if line.split('|')[0] == compare_with:
                        found_users = True
                        out_hierarchy.append(line)
            if found_users:
                out_hierarchy.append(item)
            else:
                logger.info(f'AD dep {compare_with} is empty. Remove from hierarchy.')
    return out_hierarchy

def get_all_api360_users(settings: "SettingParams", force = False):
    if not force:
        logger.info("Получение всех пользователей организации из кэша...")

    if not settings.all_users or force or (datetime.now() - settings.all_users_get_timestamp).total_seconds() > ALL_USERS_REFRESH_IN_MINUTES * 60:
        #logger.info("Получение всех пользователей организации из API...")
        settings.all_users = get_all_api360_users_from_api(settings)
        settings.all_users_get_timestamp = datetime.now()
    return settings.all_users

def get_all_api360_users_from_api(settings: "SettingParams"):
    logger.info("Получение всех пользователей организации из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    has_errors = False
    users = []
    current_page = 1
    last_page = 1
    while current_page <= last_page:
        params = {'page': current_page, 'perPage': USERS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                logger.debug(f"GET URL - {url}")
                response = requests.get(url, headers=headers, params=params)
                logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"!!! ОШИБКА !!! при GET запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        has_errors = True
                        break
                else:
                    for user in response.json()['users']:
                        if not user.get('isRobot') and int(user["id"]) >= 1130000000000000:
                            users.append(user)
                    logger.debug(f"Загружено {len(response.json()['users'])} пользователей. Текущая страница - {current_page} (всего {last_page} страниц).")
                    current_page += 1
                    last_page = response.json()['pages']
                    break

        except requests.exceptions.RequestException as e:
            logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            has_errors = True
            break

        if has_errors:
            break

    if has_errors:
        print("Есть ошибки при GET запросах. Возвращается пустой список пользователей.")
        return []
    
    return users

@dataclass
class SettingParams:
    oauth_token: str
    org_id: int
    all_users : list
    all_users_get_timestamp : datetime
    dry_run : bool
    deps_file : str
    ad_data_file : str
    ldap_host : str
    ldap_port : int
    ldap_user : str
    ldap_password : str
    ldap_base_dn : str
    ldap_search_filter : str
    hab_root_group : str
    load_ad_data_from_file : bool
    api_data_out_file : str

def get_settings():
    exit_flag = False
    oauth_token_bad = False
    settings = SettingParams (
        oauth_token = os.environ.get("OAUTH_TOKEN"),
        org_id = os.environ.get("ORG_ID"),
        all_users = [],
        all_users_get_timestamp = datetime.now(),
        dry_run = os.environ.get("DRY_RUN_ARG","false").lower() == "true",
        deps_file = os.environ.get("AD_DEPS_OUT_FILE","deps.csv"),
        ad_data_file = os.environ.get("AD_DATA_OUT_FILE","ad_data.txt"),
        ldap_host = os.environ.get('LDAP_HOST'),
        ldap_port = int(os.environ.get('LDAP_PORT')),
        ldap_user = os.environ.get('LDAP_USER'),
        ldap_password = os.environ.get('LDAP_PASSWORD'),
        ldap_base_dn = os.environ.get('LDAP_BASE_DN'),
        ldap_search_filter = os.environ.get('LDAP_SEARCH_FILTER'),
        hab_root_group = os.environ.get('HAB_ROOT_GROUP'),
        load_ad_data_from_file = os.environ.get("LOAD_AD_DATA_FROM_FILE","false").lower() == "true",
        api_data_out_file = os.environ.get("API_DATA_OUT_FILE","api_data.txt"),
    )
    
    if not settings.oauth_token:
        logger.error("OAUTH_TOKEN_ARG не установлен.")
        oauth_token_bad = True

    if not settings.org_id:
        logger.error("ORG_ID_ARG не установлен.")
        exit_flag = True

    if not (oauth_token_bad or exit_flag):
        if not check_oauth_token(settings.oauth_token, settings.org_id):
            logger.error("OAUTH_TOKEN_ARG не является действительным")
            oauth_token_bad = True

    if not settings.load_ad_data_from_file:
        if not settings.ldap_host:
            logger.error("LDAP_HOST не установлен.")
            exit_flag = True

        if not settings.ldap_port:
            logger.error("LDAP_PORT не установлен.")
            exit_flag = True

        if not settings.ldap_user:
            logger.error("LDAP_USER не установлен.")
            exit_flag = True

        if not settings.ldap_password:
            logger.error("LDAP_PASSWORD не установлен.")
            exit_flag = True

        if not settings.ldap_base_dn:
            logger.error("LDAP_BASE_DN не установлен.")
            exit_flag = True

        if not settings.ldap_search_filter:
            logger.error("LDAP_SEARCH_FILTER не установлен.")
            exit_flag = True

        if not settings.hab_root_group:
            logger.error("HAB_ROOT_GROUP не установлен.")
            exit_flag = True

    if oauth_token_bad:
        exit_flag = True
    
    if exit_flag:
        return None
    
    return settings


def check_oauth_token(oauth_token, org_id):
    """Проверяет, что токен OAuth действителен."""
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{org_id}/users?perPage=100"
    headers = {
        "Authorization": f"OAuth {oauth_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == HTTPStatus.OK:
        return True
    return False

def mask_sensitive_data(data: dict) -> dict:
    """
    Создает копию словаря с замаскированными чувствительными данными для безопасного логирования.
    
    Args:
        data (dict): Исходный словарь с данными
        
    Returns:
        dict: Копия словаря с замаскированными паролями и токенами
    """
    import copy
    
    # Создаем глубокую копию для безопасного изменения
    masked_data = copy.deepcopy(data)
    
    # Список полей, которые нужно замаскировать
    sensitive_fields = SENSITIVE_FIELDS
    
    def mask_recursive(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.lower() in sensitive_fields:
                    obj[key] = "***MASKED***"
                elif isinstance(value, (dict, list)):
                    mask_recursive(value)
        elif isinstance(obj, list):
            for item in obj:
                mask_recursive(item)
    
    mask_recursive(masked_data)
    return masked_data

def create_user_by_api(settings: "SettingParams", user: dict):

    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"POST URL: {url}")
    logger.debug(f"POST DATA: {mask_sensitive_data(user)}")
    retries = 1
    added_user = {}
    success = False
    while True:
        try:
            response = requests.post(f"{url}", headers=headers, json=user)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during POST request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Ошибка. Создание пользователя {user['nickname']} ({user['name']['last']} {user['name']['first']}) не удалось.")
                    break
            else:
                logger.info(f"Успех - пользователь {user['nickname']} ({user['name']['last']} {user['name']['first']}) создан успешно.")
                added_user = response.json()
                success = True
                break
        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    return success, added_user

def patch_user_by_api(settings: "SettingParams", user_id: int, patch_data: dict):
    logger.info(f"Изменение пользователя {user_id} в API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{user_id}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"PATCH URL: {url}")
    logger.debug(f"PATCH DATA: {mask_sensitive_data(patch_data)}")
    retries = 1
    success = False
    while True:
        try:
            response = requests.patch(f"{url}", headers=headers, json=patch_data)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Ошибка. Изменение пользователя {user_id} не удалось.")
                    break
            else:
                logger.info(f"Успех - данные пользователя {user_id} изменены успешно.")
                success = True
                break
        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    return success

def patch_department_by_api(settings: "SettingParams", department_id: int, patch_data: dict):
    logger.info(f"Изменение подразделения {department_id} в API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/departments/{department_id}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"PATCH URL: {url}")
    logger.debug(f"PATCH DATA: {mask_sensitive_data(patch_data)}")
    retries = 1
    success = False
    while True:
        try:
            response = requests.patch(f"{url}", headers=headers, json=patch_data)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Ошибка. Изменение подразделения {department_id} не удалось.")
                    break
            else:
                logger.info(f"Успех - данные подразделения {department_id} изменены успешно.")
                success = True
                break
        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    return success

def get_all_api360_departments(settings: "SettingParams"):
    logger.info("Получение всех подразделений организации из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/departments"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}

    has_errors = False
    departments = []
    current_page = 1
    last_page = 1
    while current_page <= last_page:
        params = {'page': current_page, 'perPage': DEPARTMENTS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                logger.debug(f"GET URL - {url}")
                response = requests.get(url, headers=headers, params=params)
                logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"!!! ОШИБКА !!! при GET запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        has_errors = True
                        break
                else:
                    for deps in response.json()['departments']:
                        departments.append(deps)
                    logger.debug(f"Загружено {len(response.json()['departments'])} подразделений. Текущая страница - {current_page} (всего {last_page} страниц).")
                    current_page += 1
                    last_page = response.json()['pages']
                    break

        except requests.exceptions.RequestException as e:
            logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            has_errors = True
            break

        if has_errors:
            break

    if has_errors:
        print("Есть ошибки при GET запросах. Возвращается пустой список подразделений.")
        return []
    
    return departments

def delete_department_by_api(settings: "SettingParams", department: dict):
    logger.info(f"Удаление подразделения {department['id']} ({department['name']}) из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/departments/{department['id']}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"DELETE URL: {url}")
    try:
        retries = 1
        while True:
            response = requests.delete(f"{url}", headers=headers)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при DELETE запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                logger.info(f"Успех - подразделение {department['id']} ({department['name']}) удалено успешно.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        print("Есть ошибки при DELETE запросах. Возвращается False.")
        return False

    return True


def delete_all_departments(settings: "SettingParams"):
    logger.info("Удаление всех подразделений организации...")
    departments = get_all_api360_departments(settings)
    if len(departments) == 0:
        logger.info("Нет подразделений для удаления.")
        return
    logger.info(f"Удаление {len(departments)} подразделений...")
    for department in departments:
        delete_department_by_api(settings, department)
    logger.info("Удаление всех подразделений завершено.")
    return

def create_department_by_api(settings: "SettingParams", department: dict):
    logger.info(f"Создание подразделения {department['name']} в API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/departments"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"POST URL: {url}")
    logger.debug(f"POST DATA: {department}")
    try:
        retries = 1
        while True:
            response = requests.post(f"{url}", headers=headers, json=department)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при POST запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                logger.info(f"Успех - подразделение {department['name']} создано успешно.")
                return True

    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        print("Есть ошибки при POST запросах. Возвращается False.")
        return False

    return True


def clear_dep_info_for_users(settings: "SettingParams"):
    # Функция для удаления признака членства пользователя в каком-либо департаменте
    users = get_all_api360_users(settings)
    print('Перемещение пользователей в департамент "Все"...')
    for user in users:
        if user.get("departmentId") != 1:
            patch_user_by_api(settings,
                            user_id=user.get("id"),
                            patch_data={
                                "departmentId": 1,
                            })
    print('Перемещение пользователей в департамент "Все" завершено.')
    return

def generate_api360_hierarchy(settings: "SettingParams", out_to_file: bool = False, file_suffix: str = ""):
    hierarchy = []
    departments = generate_deps_list_from_api(settings)
    departments.append({"id": 1, "path": "All", "mail": "" })
    users = get_all_api360_users(settings, True)
    if not users:
        logger.error("List of users from Yandex 360 is empty. Exit.")
        return []
    for dep in departments:
        if dep.get("mail"):
            dep_mail = '~' + dep.get("mail")
        else:
            dep_mail = ''
        hierarchy.append(f"{dep.get('id')};{dep.get('path')}{dep_mail}")
        for user in users:
            if user["departmentId"] == dep["id"]:
                user_name = f'{user["name"]["last"]} {user["name"]["first"]} {user["name"]["middle"]}'
                if user["aliases"]:
                    user_aliases = ',' + ','.join(user["aliases"])
                else:
                    user_aliases = ''
                hierarchy.append(f"{dep.get('id')};{dep.get('path')}{dep_mail}|{user['id']};{user_name}~{user['email']}{user_aliases}")

    if out_to_file:
        file_name = settings.api_data_out_file.split('.')[0] + '_' + file_suffix + '.' + settings.api_data_out_file.split('.')[1]
        with open(file_name, 'w', encoding="utf-8") as f:
            for item in hierarchy:
                f.write(item + '\n')
    return hierarchy


if __name__ == "__main__":
    denv_path = os.path.join(os.path.dirname(__file__), '.env_ldap')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)
    else:
        logger.error("Не найден файл .env_ldap. Выход.")
        sys.exit(EXIT_CODE)
    
    logger.info("\n")
    logger.info("---------------------------------------------------------------------------.")
    logger.info("Запуск скрипта.")
    
    settings = get_settings()
    
    if settings is None:
        logger.error("Проверьте настройки в файле .env_ldap и попробуйте снова.")
        sys.exit(EXIT_CODE)

    if settings.dry_run:
        logger.info('- Режим тестового прогона включен (DRY_RUN = True)! Изменения не сохраняются! -')

    #hierarchy, all_dn = build_group_hierarchy(settings)
    if settings.load_ad_data_from_file:
        hierarchy = load_heirarchy_from_file(settings.ad_data_file)
        if not check_similar_mails_in_hierarchy(hierarchy):
            #sys.exit(1)
            pass
    else:
        hierarchy, all_dn = build_group_hierarchy(settings)
        if not hierarchy:
            logger.error('\n')
            logger.error('List of current departments form Active directory is empty. Exit.\n')
            sys.exit(EXIT_CODE)
        if not check_similar_groups_in_hierarchy(all_dn):
            sys.exit(EXIT_CODE)
        if not check_similar_mails_in_hierarchy(hierarchy):
            #sys.exit(1)
            pass
    
    generate_api360_hierarchy(settings, out_to_file=True, file_suffix="start_state")
    #hierarchy = filter_empty_ad_deps(hierarchy)
    final_list = prepare_deps_list_from_ad_hab(settings, hierarchy)
    delete_deps_from_y360(settings, final_list, "same_email")
    max_levels = max([len(s['path'].split(';')) for s in final_list])
    created_deps = create_dep_from_prepared_list(settings, final_list,max_levels)
    exit_flag = False
    for item in created_deps:
        if item['360id'] == 0:
            if not settings.dry_run:
                logger.error('\n')
                logger.error(f"Department {item['path']} not saved in Yandex 360.")
                exit_flag = True
    if exit_flag:
        logger.error('\n')
        logger.error('Not all departments from Active Directory were saved in Yandex 360. Fix errors.\n')
        #sys.exit(EXIT_CODE)
    
    if not get_all_api360_users(settings):
        logger.error('\n')
        logger.error('List of users from Yandex 360 is empty. Exit.\n')
        sys.exit(EXIT_CODE)
    
    ad_users = [item for item in hierarchy if '|' in item]
    if not ad_users:
        logger.error('\n')
        logger.error('List of users from Active Directory is empty. Exit.\n')
        sys.exit(EXIT_CODE)

    assign_users_to_deps2(settings, created_deps, ad_users)
    delete_deps_from_y360(settings,final_list, "no_synced_from_ad")
    #delete_deps_with_no_users(settings)

    generate_api360_hierarchy(settings, out_to_file=True, file_suffix="end_state")

    logger.info('---------------End-----------------')

  