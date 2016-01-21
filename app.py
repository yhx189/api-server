#!flask/bin/python
import socket
import subprocess
from flask import Flask, jsonify, abort, request, make_response, url_for

app = Flask(__name__, static_url_path = "")
#app = Flask(__name__)

@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify( { 'error': 'Bad request' } ), 400)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify( { 'error': 'Not found' } ), 404)
tasks = []
with open('out.txt') as f:
    lines = f.readlines()
    for line in lines:
    	words = line.split(' ')
	task = {'src': words[1],
		'dst': words[4],
		'rtt': words[7],
		'bandwidth': words[11]}
	tasks.append(task)
print tasks

#tasks = [
 #   {
  #      'id': 1,
   #     'dst': u'165.124.182.209',
    #    'bandwidth': u'28.05', 
    #    'done': False
   # },
   # {
    #    'id': 2,
    #    'dst': u'216.58.216.78',
    #    'bandwidth': u'200.5', 
    #    'done': False
   # }
#]

def make_public_task(task):
    new_task = {}
    for field in task:
        if field == 'id':
            new_task['uri'] = url_for('get_task', task_id = task['dst'], _external = True)
        else:
            new_task[field] = task[field]
    return new_task
    
@app.route('/todo/api/v1.0/tasks', methods = ['GET'])
def get_tasks():
    return jsonify({'tasks': tasks})

@app.route('/todo/api/v1.0/hops/<task_id>', methods = ['GET'])
def get_hop(task_id):
    dest_name="google.com"
    dest_addr = socket.gethostbyname(dest_name)
    port = 33434
    max_hops = 30
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    while True:
    	recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        print "ttl is:%d"  % ttl
	recv_socket.bind(("", port))
        send_socket.sendto("", (dest_name, port))
        curr_addr = None
        curr_name = None
        try:
        	_, curr_addr = recv_socket.recvfrom(512)
                curr_addr = curr_addr[0]
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
        except socket.error:
                pass
        finally:
                send_socket.close()
                recv_socket.close()

        if curr_addr is not None:
                curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
                curr_host = "*"
        print "%d\t%s" % (ttl, curr_host)
        if ttl == int(task_id):
		ret = {'ip': curr_host}
		return jsonify( { 'task': ret } )
        ttl += 1
        if curr_addr == dest_addr or ttl > int(task_id):  #max_hops:
                break
    

@app.route('/todo/api/v1.0/tasks/<task_id>/<src_id>', methods = ['GET'])
def get_task(task_id, src_id):
    print task_id
    print src_id
    task = filter(lambda t: t['dst'][:5] == task_id[:5], tasks)
    new_task = filter(lambda t: t['src'][:5] == src_id[:5], task)
    if len(new_task) == 0:
	print "cannot find the ip " + task_id + " from the database"
        print "calling king service from server"
	print subprocess.call(["../king/bin/king", src_id, task_id], stdout=open('log.txt','a'))
	re_tasks = []
	with open('out.txt') as ff:
    		lines = ff.readlines()
    		for line in lines:
    			words = line.split(' ')
			re_task = {'src': words[1],
				'dst': words[4],
				'rtt': words[7],
				'bandwidth': words[11]}
			re_tasks.append(re_task)
	print re_tasks
	_task = filter(lambda t: t['dst'][:5] == task_id[:5], re_tasks)
    	inject_task = filter(lambda t: t['src'][:5] == src_id[:5], _task)
	print inject_task
	if len(inject_task) == 0:
		abort(404)
	print inject_task
	new_task = inject_task
    print new_task
    return jsonify( { 'task': make_public_task(new_task[0]) } )

@app.route('/todo/api/v1.0/tasks', methods = ['POST'])
def create_task():
    if not request.json or not 'title' in request.json:
        abort(400)
    task = {
        'id': tasks[-1]['id'] + 1,
        'dst': request.json['dst'],
        'bandwidth': request.json.get('bandwidth', ""),
        'done': False
    }
    tasks.append(task)
    return jsonify( { 'task': make_public_task(task) } ), 201

@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods = ['PUT'])
def update_task(task_id):
    task = filter(lambda t: t['id'] == task_id, tasks)
    if len(task) == 0:
        abort(404)
    if not request.json:
        abort(400)
    if 'title' in request.json and type(request.json['title']) != unicode:
        abort(400)
    if 'description' in request.json and type(request.json['description']) is not unicode:
        abort(400)
    if 'done' in request.json and type(request.json['done']) is not bool:
        abort(400)
    task[0]['dst'] = request.json.get('dst', task[0]['dst'])
    task[0]['bandwidth'] = request.json.get('bandwidth', task[0]['bandwidth'])
    task[0]['done'] = request.json.get('done', task[0]['done'])
    return jsonify( { 'task': make_public_task(task[0]) } )
    
@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods = ['DELETE'])
def delete_task(task_id):
    task = filter(lambda t: t['id'] == task_id, tasks)
    if len(task) == 0:
        abort(404)
    tasks.remove(task[0])
    return jsonify( { 'result': True } )
    
if __name__ == '__main__':
    app.run(debug = True, host ='0.0.0.0')
