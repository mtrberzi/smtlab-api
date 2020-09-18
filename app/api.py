from flask import Flask, request, g
from flask_restful import Api, Resource, abort
from flask_httpauth import HTTPBasicAuth
import json
import base64
import boto3
import datetime
from functools import wraps

from app import app, db
from app.models import Benchmark, Instance, Solver, Run, Result, SolverResponseEnum, ValidationResult, ValidationEnum, User, Permission, PermissionEnum
from app.storage import ObjectStorageError, FileSystemObjectStorage

def get_object_storage_client():
    storage_type = app.config['OBJECT_STORAGE']
    if storage_type == "filesystem":
        return FileSystemObjectStorage(app.config['OBJECT_STORAGE_FILESYSTEM_BASE'])
    else:
        raise ValueError("Unknown object storage type {}".format(storage_type))

api = Api(app)
auth = HTTPBasicAuth()

def needs_permission(perm):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not g.user.has_permission(perm):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

class BenchmarkListAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self):
        all_benchmarks = Benchmark.query.all()
        response = []
        for benchmark in all_benchmarks:
            response.append(benchmark.json_obj())
        return response

    @auth.login_required
    @needs_permission(PermissionEnum.upload_benchmark)
    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        if "name" not in json_data:
            abort(400, description="Benchmark name must be specified")
        new_benchmark = Benchmark(name=json_data["name"])
        db.session.add(new_benchmark)
        db.session.commit()
        return new_benchmark.json_obj()

api.add_resource(BenchmarkListAPI, '/benchmarks', endpoint = 'benchmark_list')

class BenchmarkAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        else:
            return benchmark.json_obj()

    # Upload instances
    @auth.login_required
    @needs_permission(PermissionEnum.upload_benchmark)
    def post(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        objstor = get_object_storage_client()
        objstor.ensure_bucket_exists(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'])
        instance_data = []
        for inst in json_data:
            if 'name' not in inst or 'body' not in inst:
                abort(400, description="Instance must specify 'name' and 'body'")
            instance = Instance(name=inst['name'], benchmark=benchmark)
            db.session.add(instance)
            instance_data.append( (instance, inst['body']) )
        db.session.commit()
        for instance, body in instance_data:
            # filter out (get-model): calling this automatically is an error if the answer is "UNSAT"
            sanitized_body = body.replace("(get-model)", "")
            objstor.put(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'], instance.object_key(), sanitized_body.encode('UTF-8'))
        response = []
        for instance, body in instance_data:
            response.append(instance.json_obj_summary())
        return response

    @auth.login_required
    @needs_permission(PermissionEnum.upload_benchmark)
    def delete(self, id):
        Benchmark.query.filter(Benchmark.id == id).delete()
        db.session.commit()
        return ('', 204)

api.add_resource(BenchmarkAPI, '/benchmarks/<int:id>', endpoint = 'benchmark')

class BenchmarkRunsAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        runs = []
        for run in benchmark.runs.all():
            runs.append(run.json_obj_summary())
        return runs
api.add_resource(BenchmarkRunsAPI, '/benchmarks/<int:id>/runs', endpoint = 'benchmark_runs')

class InstanceListAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        instances = []
        for inst in benchmark.instances.all():
            instances.append(inst.json_obj_summary())
        return instances
api.add_resource(InstanceListAPI, '/benchmarks/<int:id>/instances', endpoint = 'instance_list')

class InstanceAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        instance = Instance.query.get(id)
        if instance is None:
            abort(404)
        inst = instance.json_obj_summary()
        objstor = get_object_storage_client()
        objstor.ensure_bucket_exists(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'])
        inst['body'] = objstor.get(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'], instance.object_key()).decode('utf-8')
        return inst

    @auth.login_required
    @needs_permission(PermissionEnum.upload_benchmark)
    def put(self, id):
        abort(500) # TODO
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        
api.add_resource(InstanceAPI, '/instances/<int:id>', endpoint = 'instance')

class SolverListAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self):
        all_solvers = Solver.query.all()
        response = []
        for solver in all_solvers:
            response.append(solver.json_obj_summary())
        return response

    @auth.login_required
    @needs_permission(PermissionEnum.upload_solver)
    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        if "name" not in json_data or "validation_solver" not in json_data or "base64_binary" not in json_data:
            abort(400, description="Solver must specify 'name', 'validation_solver', and 'base64_binary'")
        if "default_arguments" in json_data:
            args = json_data["default_arguments"]
        else:
            args = ""
        solver_bytes = base64.b64decode(json_data["base64_binary"].encode('ascii'))
        objstor = get_object_storage_client()
        objstor.ensure_bucket_exists(app.config['OBJECT_STORAGE_SOLVER_BUCKET'])
        solver = Solver(name=json_data["name"], validation_solver=json_data["validation_solver"], default_arguments=args)
        db.session.add(solver)
        db.session.commit()
        objstor.put(app.config['OBJECT_STORAGE_SOLVER_BUCKET'], solver.object_key(), solver_bytes)
        return solver.json_obj_summary()

api.add_resource(SolverListAPI, '/solvers', endpoint = 'solver_list')

class SolverAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        solver = Solver.query.get(id)
        if solver is None:
            abort(404)
        solv = solver.json_obj_summary()
        objstor = get_object_storage_client()
        solver_binary = objstor.get(app.config['OBJECT_STORAGE_SOLVER_BUCKET'], solver.object_key())
        solv['base64_binary'] = base64.b64encode(solver_binary).decode('ascii')
        return solv

api.add_resource(SolverAPI, '/solvers/<int:id>', endpoint = 'solver')

class SolverRunAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        solver = Solver.query.get(id)
        if solver is None:
            abort(404)
        runs = []
        for run in solver.runs.all():
            runs.append(run.json_obj_summary())
        return runs
api.add_resource(SolverRunAPI, '/solvers/<int:id>/runs', endpoint = 'solver_runs')

class RunListAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self):
        all_runs = Run.query.all()
        response = []
        for run in all_runs:
            response.append(run.json_obj_summary())
        return response

    # start new run
    @auth.login_required
    @needs_permission(PermissionEnum.start_run)
    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        if "benchmark_id" not in json_data or "solver_id" not in json_data or "performance" not in json_data:
            abort(400, description="Run must specify 'benchmark_id', 'solver_id', and 'performance'")
        benchmark = Benchmark.query.get(json_data["benchmark_id"])
        if benchmark is None:
            abort(400, description="Invalid benchmark_id")
        solver = Solver.query.get(json_data["solver_id"])
        if solver is None:
            abort(400, description="Invalid solver_id")
        if "arguments" in json_data:
            args = json_data["arguments"]
        else:
            args = solver.default_arguments
        if "description" in json_data:
            description = json_data["description"]
        else:
            description = ""
        performance = json_data["performance"]
        run = Run(benchmark=benchmark, solver=solver, arguments=args, performance=performance, description=description, start_date=datetime.datetime.now())
        db.session.add(run)
        db.session.commit()
        # send message to scheduler
        try:
            client = boto3.resource('sqs', endpoint_url=app.config['QUEUE_URL'], region_name='elasticmq', aws_access_key_id='x', aws_secret_access_key='x', use_ssl=False)
            queue = client.get_queue_by_name(QueueName="scheduler")
            scheduler_msg = {'action': 'schedule', 'id': run.id}
            queue.send_message(MessageBody=json.dumps(scheduler_msg))
        except Exception as e:
            print(e)
            abort(500, description="Server-side message queue error")
        return run.json_obj_summary()
        
api.add_resource(RunListAPI, '/runs', endpoint='run_list')

class RunAPI(Resource):
    # get run summary
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        run = Run.query.get(id)
        if run is None:
            abort(404)
        return run.json_obj_summary()

    # run control
    @auth.login_required
    @needs_permission(PermissionEnum.start_run)
    def post(self, id):
        run = Run.query.get(id)
        if run is None:
            abort(404)
        
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        if "action" not in json_data:
            abort(400, description="Run control must specify 'action'")
        action = json_data['action']
        if action == "reschedule":
            scheduler_msg = {'action': 'schedule', 'id': run.id}
            try:
                c = boto3.resource('sqs', endpoint_url=app.config['QUEUE_URL'], region_name='elasticmq', aws_access_key_id='x', aws_secret_access_key='x', use_ssl=False)
                queue = c.get_queue_by_name(QueueName='scheduler')
                response = queue.send_message(MessageBody=json.dumps(scheduler_msg))
            except Exception as e:
                abort(500)
        else:
            abort(400, description="Invalid control action")
            
api.add_resource(RunAPI, '/runs/<int:id>', endpoint = 'run')

class RunResultListAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        run = Run.query.get(id)
        if run is None:
            abort(404)
        results = [r.json_obj_summary() for r in run.results.all()]
        return results

    @auth.login_required
    @needs_permission(PermissionEnum.post_results)
    def post(self, id):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data specified")
        new_result_objs = []
        for result in json_data:
            if 'instance_id' not in result or 'result' not in result or 'stdout' not in result or 'runtime' not in result:
                abort(400, description="Result object must specify 'instance_id', 'result', 'stdout', and 'runtime'")
            if 'node_name' in result:
                node_name = result['node_name']
            else:
                node_name = ""
            db_result = Result(run_id=id, instance_id = result['instance_id'], result=SolverResponseEnum[result['result']], stdout=result['stdout'], runtime=result['runtime'], node_name=node_name)
            db.session.add(db_result)
            new_result_objs.append(db_result)
        db.session.commit()
        return [x.json_obj_summary() for x in new_result_objs]

api.add_resource(RunResultListAPI, '/runs/<int:id>/results', endpoint = 'run_result_list')

class RunResultAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        result = Result.query.get(id)
        if result is None:
            abort(404)
        details = result.json_obj_details()
        validations = []
        # query for validations:
        # - all validation results directly validating this one
        # - all results from validation solvers on the same instance, in other runs
        for v in result.validation_results.all():
            validations.append({'solver_id': v.solver_id, 'validation': v.validation.name})
        for rr, rn, rs in db.session.query(Result, Run, Solver).filter(Result.instance_id == result.instance_id).filter(Result.run_id != result.run_id).filter(Result.run_id == Run.id).filter(Run.solver_id == Solver.id).filter(Solver.validation_solver==True).all():
            validations.append({'solver_id': rs.id, 'result': rr.result.name})
        details['validations'] = validations
        return details

api.add_resource(RunResultAPI, '/results/<int:id>', endpoint = 'result_details')

class ValidationResultAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.read)
    def get(self, id):
        result = Result.query.get(id)
        if result is None:
            abort(404)
        validations = [v.json_obj_summary() for v in run.validation_results.all()]
        return validations

    @auth.login_required
    @needs_permission(PermissionEnum.post_results)
    def post(self, id):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data specified")
        new_validation_objs = []
        for validation_result in json_data:
            if 'solver_id' not in validation_result or 'validation' not in validation_result or 'stdout' not in validation_result:
                abort(400, description="Validation result object must specify 'solver_id', 'validation', and 'stdout'")
            if 'node_name' in validation_result:
                node_name = validation_result['node_name']
            else:
                node_name = ""
            db_validation_result = ValidationResult(result_id=id, solver_id=validation_result['solver_id'], validation=ValidationEnum[validation_result["validation"]], stdout=validation_result["stdout"], node_name=node_name)
            db.session.add(db_validation_result)
            new_validation_objs.append(db_validation_result)
        db.session.commit()
        return [v.json_obj_summary() for v in new_validation_objs]

api.add_resource(ValidationResultAPI, '/results/<int:id>/validation', endpoint = 'validation_results')

class UserCreationAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.admin_user)
    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data specified")
        if 'username' not in json_data or 'password' not in json_data or 'permissions' not in json_data:
            abort(400, description="User creation must specify 'username', 'password', and 'permissions'")
        existing_user = User.query.filter_by(username=json_data['username']).first()
        if existing_user is not None:
            abort(400, description="User exists")
        user = User(username=json_data['username'])
        user.hash_password(json_data['password'])
        for perm in json_data['permissions']:
            user.permissions.append(Permission(permission=PermissionEnum[perm]))
        db.session.add(user)
        db.session.commit()
        return user.json_obj_summary()

api.add_resource(UserCreationAPI, '/users/create', endpoint = 'create_user')

class ChangePasswordAPI(Resource):
    @auth.login_required
    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data specified")
        if 'username' not in json_data or 'password' not in json_data:
            abort(400, description="Request body must specify 'username' and 'password'")
        if json_data['username'] == g.user.username:
            needed_perm = PermissionEnum.change_password
        else:
            needed_perm = PermissionEnum.change_other_password
        if not g.user.has_permission(needed_perm):
            abort(403)
        user = User.query.filter_by(username=json_data['username']).first()
        if user is None:
            abort(404)
        user.hash_password(json_data['password'])
        db.session.add(user)
        db.session.commit()

        return user.json_obj_summary()

api.add_resource(ChangePasswordAPI, '/users/change_password', endpoint = 'change_password')

class GrantPermissionsAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.admin_user)
    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data specified")
        if 'username' not in json_data or 'permissions' not in json_data:
            abort(400, description="Request body must specify 'username' and 'permissions'")
        user = User.query.filter_by(username=json_data['username']).first()
        if not user:
            abort(404)
        new_perms = [PermissionEnum[x] for x in json_data['permissions']]
        existing_perms = [x.permission for x in user.permissions]
        for new_perm in new_perms:
            if new_perm not in existing_perms:
                user.permissions.append(new_perm)
        db.session.add(user)
        db.session.commit()

        return user.json_obj_summary()
api.add_resource(GrantPermissionsAPI, '/users/permissions', endpoint = 'grant_permissions')

valid_queues = ['scheduler', 'performance', 'regression']

class MessageQueueAPI(Resource):
    @auth.login_required
    @needs_permission(PermissionEnum.message_queue)
    def get(self, queue):
        if queue not in valid_queues:
            abort(404)
        client = boto3.resource('sqs', endpoint_url=app.config['QUEUE_URL'], region_name='elasticmq', aws_access_key_id='x', aws_secret_access_key='x', use_ssl=False)
        queue = client.get_queue_by_name(QueueName=queue)
        msgs = queue.receive_messages(MaxNumberOfMessages=1, WaitTimeSeconds=0)
        if len(msgs) == 0:
            return []
        else:
            msg = msgs[0]
            body = msg.body
            msg.delete()
            return [body]

    @auth.login_required
    @needs_permission(PermissionEnum.message_queue)
    def post(self, queue):
        if queue not in valid_queues:
            abort(404)
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data specified")
        client = boto3.resource('sqs', endpoint_url=app.config['QUEUE_URL'], region_name='elasticmq', aws_access_key_id='x', aws_secret_access_key='x', use_ssl=False)
        queue = client.get_queue_by_name(QueueName=queue)
        queue.send_message(MessageBody=json.dumps(json_data))
        return []

api.add_resource(MessageQueueAPI, '/queues/<queue>', endpoint = 'message_queue')
