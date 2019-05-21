import argparse
import json


def read_vulnerability(data, id):
    advisories = data['advisories']
    vulnerability = advisories[str(id)]
    title = vulnerability['title']
    severity = vulnerability['severity']
    url = vulnerability['url']
    return {'title': title, 'severity': severity, 'url': url}


def read_resolve(data, resolve):
    id = resolve['id']
    path = resolve['path']
    dev = resolve['dev']
    optional = resolve['optional']
    bundled = resolve['bundled']
    vulnerability = read_vulnerability(data, id)
    return {'id': id, 'path': path, 'dev': dev, 'optional': optional, 'bundled': bundled, 'vulnerability': vulnerability}


def read_resolves(data, action):
    resolves_read = []
    resolves = action['resolves']
    for resolve in resolves:
        resolve_read = read_resolve(data, resolve)
        resolves_read.append(resolve_read)
    return resolves_read


def parse_path(path):
    parts = path.split('>')
    return parts


def path_root(path_parts):
    return path_parts[0]


def join_path(path_parts):
    return ' > '.join(path_parts)


def write_line(f, length, type):
    top_left_corner = '┌'
    top_right_corner = '┐'
    bottom_left_corner = '└'
    bottom_right_corner = '┘'
    horizontal_line = '─'
    edge = '│'
    line = ''

    for x in range(length):
        line += horizontal_line

    if type == 'top':
        f.write(f'{top_left_corner}{line}{top_right_corner}\n')
    elif type == 'bottom':
        f.write(f'{bottom_left_corner}{line}{bottom_right_corner}\n')
    else:
        f.write(f'{edge}{line}{edge}\n')


def write_name_value(f, length, name, value):
    column_one_width = 15
    padding = 2
    edge = '│'

    column_one = name
    for x in range(column_one_width - len(name)):
        column_one += ' '

    column_two = ' ' + value
    for x in range(length - (column_one_width + len(value) + padding)):
        column_two += ' '

    f.write(f'{edge}{column_one}{edge}{column_two}{edge}\n')


def write_vulnerability(f, resolve):
    vulnerability = resolve['vulnerability']
    severity = vulnerability['severity'].title()
    title = vulnerability['title']
    module = resolve['module']
    project = resolve['project']
    line_length = 100

    write_line(f, line_length, 'top')
    write_name_value(f, line_length, severity, title)
    write_line(f, line_length, None)
    write_name_value(f, line_length, 'Package', module)
    write_line(f, line_length, None)
    dev_text = ''
    if resolve['dev']:
        dev_text = ' [dev]'
    write_name_value(f, line_length, 'Dependency of', path_root(parse_path(resolve['path'])) + dev_text)
    write_line(f, line_length, None)
    write_name_value(f, line_length, 'Path', join_path(parse_path(resolve['path'])))
    write_line(f, line_length, None)
    write_name_value(f, line_length, 'More info', vulnerability['url'])
    write_line(f, line_length, None)
    write_name_value(f, line_length, 'Project', project)
    write_line(f, line_length, 'bottom')


def read_action(action):
    action_name = action['action']
    module = action['module']
    target = action.get('target', '')
    # depth only exists for update actions
    depth = action.get('depth', '')
    return action_name, module, target, depth


def filter_vulnerabilities(vulnerabilities, type):
    if type == 'both':
        return vulnerabilities

    filtered = []
    for vulnerability in vulnerabilities:
        if type == 'dependencies' and not vulnerability['dev']:
            filtered.append(vulnerability)
        elif type == 'devDependencies' and vulnerability['dev']:
            filtered.append(vulnerability)
    return filtered


def sort_vulnerabilities(vulnerabilities):
    def severity_conversion(severity):
        if severity == 'critical':
            return 1
        elif severity == 'high':
            return 2
        elif severity == 'moderate':
            return 3
        elif severity == 'low':
            return 4
        elif severity == 'info':
            return 5

    def sorting(a):
        return severity_conversion(a['vulnerability']['severity'])

    return sorted(vulnerabilities, key=sorting)


def gather_vulnerabilities(data, project):
    vulnerability_data = []
    actions = data['actions']
    for action in actions:
        action_name, module, target, depth = read_action(action)
        resolves = read_resolves(data, action)
        for resolve in resolves:
            resolve['module'] = module
            resolve['target'] = target
            resolve['project'] = project
            vulnerability_data.append(resolve)

    return vulnerability_data


def write_vulnerabilities(f, vulnerabilities):
    for vulnerability in vulnerabilities:
        write_vulnerability(f, vulnerability)


def amalgamates(output, type, inputs):
    f = open(output, 'w')
    audit_files = inputs.split(',')
    all_vulnerabilities = []
    for audit in audit_files:
        vulnerabilities = gather_vulnerabilities(json.loads(open(audit).read()), audit)
        all_vulnerabilities = all_vulnerabilities + vulnerabilities

    filtered_vulnerabilities = filter_vulnerabilities(all_vulnerabilities, type)
    sorted_vulnerabilities = sort_vulnerabilities(filtered_vulnerabilities)
    write_vulnerabilities(f, sorted_vulnerabilities)
    f.close()


parser = argparse.ArgumentParser()
parser.add_argument('output', help='Output file name')
parser.add_argument('type', help='Type of dependencies, devDependencies, dependencies or both')
parser.add_argument('inputs', help='Input audit files')
args = parser.parse_args()

amalgamates(args.output, args.type, args.inputs)

