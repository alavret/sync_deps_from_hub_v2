import os
import csv
from datetime import datetime
from dotenv import load_dotenv
from lib.y360_api.api_script import API360

def clear_dep_info_for_users():
    # Функция для удаления признака членства пользователя в каком-либо департаменте
    print('Get all org users from API...')
    users = organization.get_all_users()
    print('Done.')
    print('Clear link between departments and users...')
    for user in users:
        if user.get("departmentId") != 1:
            organization.patch_user_info(
                            uid=user.get("id"),
                            user_data={
                                "departmentId": 1,
                            })
    print('Done.')
    return


def delete_all_departments():
    # Функцция по удалению департаментов в орге, предварительно должна быть вызвана функция очистки пользователя от признака членства в департаменте
    clear_dep_info_for_users()

    print('Delete all departments...')
    while True:
        organization.wipe_all_departments()
        if len(organization.get_departments_list()) == 1:
            break
    print('Done.')
    return


def create_dep_from_prepared_list(deps_list, max_levels):
    # Фнункция создания департамента из предварительно подготовленного списка
    print('Create new departments..')
    api_prepared_list = generate_deps_list_from_api()
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
                                    "parentId": d['360id']
                                }
                    organization.post_create_department(department_info)
                    need_update_deps = True
            #all_deps_from_api = organization.get_departments_list()
            if need_update_deps:
                api_prepared_list = generate_deps_list_from_api()
            for item in deps_to_add:
                # Ищем в списке департаментов в 360 конкретное значение
                #d = next(i for i in all_deps_from_api if i['name'] == item['current'] and i['parentId'] == item['prevId'])
                d = next(i for i in api_prepared_list if i['path'] == item['path'])
                #Обновляем информацию в final_list для записанных в 360 департаментов
                item['360id'] = d['id']
    print('Done')


def prepare_deps_list_from_raw_data(raw_data):
    """     Входящий список должен быть в таком формате:
            34;Barb Corp
            35;Yandry Corp
            36;Yandry Corp;ИТ
            37;Barb Corp;ИТ
            38;Yandry Corp;Дирекция
            39;Barb Corp;ИТ;Отдел сопровождения
            40;Yandry Corp;ИТ;Отдел внедрения 
    """

    temp_list = [{'current': 'All', 'prev': 'None', 'level': 0, '360id': 1, 'prevId': 0, 'path': 'All'}]
    max_levels = 1
    # Формируем уникальный список всей иерархии подразделений (каждое подразделение имеет отдельную строку в списке)
    for item in raw_data:
        length = len(item['path'].split(';'))
        if length > max_levels:
            max_levels = length
        for i in range(0,length):
            if i == 0:
                temp_list.append({'current':item['path'].split(';')[i], 'prev':'All', 'level':i+1, '360id':0, 'prevId':0, 'path':''})
            else:
                temp_list.append({'current':item['path'].split(';')[i], 'prev':';'.join(item['path'].split(';')[:i]), 'level':i+1, '360id':0, 'prevId':0, 'path':''})
    # Фильрация уникальных значений из списка словарей, полученного на предыдущем этапе
    final_list = [dict(t) for t in {tuple(d.items()) for d in temp_list}]
    # Заполнение поля path (полный путь к подразделению)
    for item in final_list:
        if not item['current'] == 'All':
            if item['prev'] == 'All':
                item['path'] = item['current']
            else:
                item['path'] = f'{item["prev"]};{item["current"]}'
    # Добавление в 360
    return final_list


def create_deps_from_scratch_entry():
    answer = input("You selected to DELETE AND CREATE DEPARTMENTS from file. Continue? (Y/n): ")
    if answer.upper() in ["Y", "YES"]:
        # Читаем файл из файла-образца
        deps_data = read_deps_file('DEPS_FILE_NAME')
        if len(deps_data) == 0:
            return
        
        delete_all_departments()        
        
        final_list = prepare_deps_list_from_raw_data(deps_data)
        max_levels = max([len(s['path'].split(';')) for s in deps_data])
        # Добавление в 360
        create_dep_from_prepared_list(final_list,max_levels)


def read_deps_file(os_env_file_name):
    deps_file_name = os.environ.get(os_env_file_name)
    if not os.path.exists(deps_file_name):
        full_path = os.path.join(os.path.dirname(__file__), deps_file_name)
        if not os.path.exists(full_path):
            print (f'ERROR! Input file {deps_file_name} not exist!')
            return []
        else:
            deps_file_name = full_path
    
    ### Another way to read file with needed transfromations
    # with open(deps_file_name, 'r') as csvfile:
    #     header = csvfile.readline().split(";")
    #     for line in csvfile:
    #         fields = line.split(";")
    #         entry = {}
    #         for i,value in enumerate(fields):
    #             entry[header[i].strip()] = value.strip()
    #         data.append(entry)
    # print(data)

    data = []
    data_for_print = []
    with open(deps_file_name, 'r') as csvfile:
        
        for line in csvfile:
            entry_for_print = {}
            entry= {}
            fields = line.split(";")
            fields = [x.strip() for x in fields]            
            entry_for_print[fields[0]] = ';'.join(fields[1:])
            data_for_print.append(entry_for_print)
            entry['id'] = fields[0]
            entry['path'] = ';'.join(fields[1:])
            data.append(entry)
    print('*' * 100)
    print('Data to import')
    print('-' * 100)
    for line in data_for_print:
        print(line)
    print('-' * 100)
    answer = input("Continue to import? (Y/n): ")
    if answer.upper() in ["Y", "YES"]:
        return data
    else:
        return []
        

def del_all_deps():
    answer = input("You selected to DELETE ALL DEPARTMENTS. Continue? (Y/n): ")
    if answer.upper() in ["Y", "YES"]:
        delete_all_departments()


def delete_selected_deps(deps_list):
    if len(deps_list) == 0:
        return
    for item in deps_list[::-1]:
        if item['id'] > 1:
            organization.delete_department_by_id(item['id'])


def generate_deleted_deps():
    #Для анализа используется файл DEPS_UNUSED_FILE 
    file_data = read_deps_file('DEPS_UNUSED_FILE')
    if len(file_data) == 0:
        print('There are no departments to delete.')
        return []
    api_data = generate_deps_list_from_api()
    deps_to_delete = []
    for file in file_data:
        found = False
        for api in api_data:
            if file['path'] == api['path']:
                found = True
                deps_to_delete.append(api)
            elif api['path'].startswith(f'{file["path"]};'):
                found = True
                deps_to_delete.append(api)
        if not found:
            deps_to_delete.append({'id':-1,'path':file['path']})
    return deps_to_delete


def delete_selected_deps_entry():
    deps_to_delete = generate_deleted_deps()
    if len(deps_to_delete) == 0:
        return
    
    print('Selected departments will be deleted.')
    for item in deps_to_delete:
        if item['id'] != -1:
            print(item)

    d = next((i for i in deps_to_delete if i['id'] == -1), None)
    if d is not None:
        print('Selected departments NOT EXIST IN ORGANIZATION.')
        for item in deps_to_delete:
            if item['id'] == -1:
                print(item)

    answer = input("Continue? (Y/n): ")
    if answer.upper() in ["Y", "YES"]:
        delete_selected_deps(deps_to_delete)
    print('Done.')


def generate_unique_file_name(name): 
    name_without_ext = '.'.join(name.split('.')[0:-1])
    file_ext = name.split('.')[-1]
    now = datetime.now()
    file_var_part  = now.strftime("%Y%m%d_%H%M%S")
    final_file_name = f'{name_without_ext}_{file_var_part}.{file_ext}'
    return final_file_name


def generate_deps_list_from_api():
    all_deps_from_api = organization.get_departments_list()
    if len(all_deps_from_api) == 1:
        #print('There are no departments in organozation! Exit.')
        return []
    all_deps = []
    for item in all_deps_from_api:        
        path = item['name'].strip()
        prevId = item['parentId']
        if prevId > 0:
            while not prevId == 1:
                d = next(i for i in all_deps_from_api if i['id'] == prevId)
                path = f'{d["name"].strip()};{path}'
                prevId = d['parentId']
            element = {'id':item['id'], 'parentId':item['parentId'], 'path':path}
            all_deps.append(element)
    return all_deps

def generate_deps_list_from_api_and_count_users():
    users = organization.get_all_users()
    if not users:
        return []
    all_deps_from_api = organization.get_departments_list()
    if len(all_deps_from_api) == 1:
        #print('There are no departments in organozation! Exit.')
        return []
    all_deps = []
    for item in all_deps_from_api:        
        path = item['name'].strip()
        users_count = sum( user['departmentId'] == item['id'] for user in users)
        prevId = item['parentId']
        if prevId > 0:
            while not prevId == 1:
                users_count += sum( user['departmentId'] == prevId for user in users)
                d = next(i for i in all_deps_from_api if i['id'] == prevId)
                path = f'{d["name"].strip()};{path}'
                prevId = d['parentId']
            element = {'id':item['id'], 'parentId':item['parentId'], 'path':path, 'users_count':users_count}
            all_deps.append(element)
    return all_deps


def load_dep_info_to_file():
    all_deps = generate_deps_list_from_api()
    write_deps_to_file('DEPS_BACKUP_FILE', all_deps)


def write_deps_to_file(os_env_file_name, deps_list):
    file_name = os.environ.get(os_env_file_name)  
    file_name_random = generate_unique_file_name(file_name)
    while os.path.exists(file_name_random):
        file_name_random = generate_unique_file_name(file_name)

    if len(deps_list) == 0:
        print('There are no departments to export! Exit.')
    else:        
        with open(file_name_random, 'w') as file:
            for item in deps_list:
                file.write(f'{item["id"]};{item["path"]}\n')
        print(f'Data uploaded to {file_name_random} file.')


def generate_unused_deps():
    #Для анализа используется файл DEPS_FILE_NAME (как источник используемых и актуальных департаментов)
    file_data = read_deps_file('DEPS_FILE_NAME')
    api_data = generate_deps_list_from_api()
    deps_to_delete = []
    for api in api_data:
        found = False
        for file in file_data:
            if file['path'] == api['path']:
                found = True
                break
            elif file['path'].startswith(f'{api["path"]};'):
                found = True
                break
        if not found:
            if api['parentId'] > 0:
                deps_to_delete.append(api)
    return deps_to_delete

def export_empty_deps_to_file():

    api_deps = generate_deps_list_from_api_and_count_users()
    if not api_deps:
       print(f'No deps were returned from Y360.') 
       return

    deps_to_delete = list( l for l in api_deps if l['users_count'] == 0 )
    write_deps_to_file('DEPS_UNUSED_FILE', deps_to_delete) 
    return 

def export_unused_deps_to_file():
    all_deps = generate_unused_deps()
    write_deps_to_file('DEPS_UNUSED_FILE', all_deps)    


def update_deps_from_file():
    file_data = read_deps_file('DEPS_FILE_NAME')
    if not file_data:
        return
    api_data = generate_deps_list_from_api()
    deps_to_delete = []
    for api in api_data:
        found = False
        for file in file_data:
            if file['path'] == api['path']:
                found = True
                break
        if not found:
            deps_to_delete.append(api)

    final_list = prepare_deps_list_from_raw_data(file_data)
    max_levels = max([len(s['path'].split(';')) for s in file_data])
    # Добавление в 360
    create_dep_from_prepared_list(final_list,max_levels)


def main_menu():

    while True:
        print(" ")
        print("Select option:")
        print("1. Delete all departments and create them from file.")
        print("2. Update departments from file.")
        print("3. Export existing departments to file.")
        print("4. Export unused (not in initial file) departments to file.")
        print("5. Export empty (without users) departments to file.")
        print("6. Delete unused departments.")
        print("7. Delete all departments.")
        print("8. Output all users to file.")
        print("0. Exit")

        choice = input("Enter your choice (0-8): ")

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            create_deps_from_scratch_entry()
        elif choice == "2":
            update_deps_from_file()
        elif choice == "3":
            load_dep_info_to_file()
        elif choice == "4":
            export_unused_deps_to_file() 
        elif choice == "5":
            export_empty_deps_to_file()        
        elif choice == "6":
            delete_selected_deps_entry()
        elif choice == "7":
            del_all_deps()
        elif choice == "8":
            organization.get_all_users(True)
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)
    
    organization = API360(os.environ.get('orgId'), os.environ.get('access_token'))
    
    main_menu()

    