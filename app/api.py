from flask import Flask, request
from flask_restful import Api, Resource, abort
import json
import base64
import stomp

from app import app, db
from app.models import Benchmark, Instance, Solver, Run, Result, SolverResponseEnum
from app.storage import ObjectStorageError, FileSystemObjectStorage

def get_object_storage_client():
    storage_type = app.config['OBJECT_STORAGE']
    if storage_type == "filesystem":
        return FileSystemObjectStorage(app.config['OBJECT_STORAGE_FILESYSTEM_BASE'])
    else:
        raise ValueError("Unknown object storage type {}".format(storage_type))

api = Api(app)

class BenchmarkListAPI(Resource):    
    def get(self):
        all_benchmarks = Benchmark.query.all()
        response = []
        for benchmark in all_benchmarks:
            response.append(benchmark.json_obj())
        return response

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
    def get(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        else:
            return benchmark.json_obj()

    # Upload instances
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
            instance_data.append( (instance, inst['body'].encode('utf-8')) )
        db.session.commit()
        for instance, body in instance_data:
            objstor.put(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'], instance.object_key(), body)
        response = []
        for instance, body in instance_data:
            response.append(instance.json_obj_summary())
        return response

    def delete(self, id):
        Benchmark.query.filter(Benchmark.id == id).delete()
        db.session.commit()
        return ('', 204)

api.add_resource(BenchmarkAPI, '/benchmarks/<int:id>', endpoint = 'benchmark')

class BenchmarkRunsAPI(Resource):
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
    def get(self, id):
        instance = Instance.query.get(id)
        if instance is None:
            abort(404)
        inst = instance.json_obj_summary()
        objstor = get_object_storage_client()
        objstor.ensure_bucket_exists(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'])
        inst['body'] = objstor.get(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'], instance.object_key()).decode('utf-8')
        return inst

    def put(self, id):
        abort(500) # TODO
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        
api.add_resource(InstanceAPI, '/instances/<int:id>', endpoint = 'instance')

class SolverListAPI(Resource):
    def get(self):
        all_solvers = Solver.query.all()
        response = []
        for solver in all_solvers:
            response.append(solver.json_obj_summary())
        return response

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
    def get(self):
        all_runs = Run.query.all()
        response = []
        for run in all_runs:
            response.append(run.json_obj_summary())
        return response

    # start new run
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
        performance = json_data["performance"]
        run = Run(benchmark=benchmark, solver=solver, arguments=args, performance=performance)
        db.session.add(run)
        db.commit()
        # send message to scheduler
        try:
            c = stomp.Connection(app.config['QUEUE_CONNECTION'])
            c.connect(app.config['QUEUE_USERNAME'], app.config['QUEUE_PASSWORD'], wait=True)
            scheduler_msg = {'action': 'schedule', 'id': run.id}
            c.send(body=json.dumps(scheduler_msg), destination='queue/scheduler')
            c.disconnect()
        except Exception as e:
            pass
        return run.json_obj_summary()
        
api.add_resource(RunListAPI, '/runs', endpoint='run_list')

class RunAPI(Resource):
    # get run summary
    def get(self, id):
        run = Run.query.get(id)
        if run is None:
            abort(404)
        return run.json_obj_summary()

    # run control
    def post(self, id):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        if "action" not in json_data:
            abort(400, description="Run control must specify 'action'")
        action = json_data['action']
        if action == "reschedule":
            try:
                c = stomp.Connection(app.config['QUEUE_CONNECTION'])
                c.connect(app.config['QUEUE_USERNAME'], app.config['QUEUE_PASSWORD'], wait=True)
                scheduler_msg = {'action': 'schedule', 'id': run.id}
                c.send(body=json.dumps(scheduler_msg), destination='queue/scheduler')
                c.disconnect()
            except Exception as e:
                abort(500)
        else:
            abort(400, description="Invalid control action")
            
api.add_resource(RunAPI, '/runs/<int:id>', endpoint = 'run')

class RunResultListAPI(Resource):
    def get(self, id):
        abort(500) # TODO

    def post(self, id):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data specified")
        # TODO
        abort(500)

api.add_resource(RunResultListAPI, '/runs/<int:id>/results', endpoint = 'run_result_list')
