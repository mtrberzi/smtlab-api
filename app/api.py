from flask import Flask, request
from flask_restful import Api, Resource, abort
from flask_marshmallow import Marshmallow
from marshmallow import ValidationError

from app import app, db
from app.models import Benchmark, Instance

api = Api(app)
ma = Marshmallow(app)

class BenchmarkListEntrySchema(ma.Schema):
    id = ma.Int(dump_only=True)
    name = ma.Str()

benchmark_schema = BenchmarkListEntrySchema()
benchmarks_schema = BenchmarkListEntrySchema(many=True)

class InstanceSummary(ma.Schema):
    id = ma.Int()
    name = ma.Str()
instance_summary_schema = InstanceSummary(many=True)

class InstanceSchema(ma.Schema):
    id = ma.Int(dump_only=True)
    name = ma.Str()
    body = ma.Str()

instances_schema = InstanceSchema(many=True)

class BenchmarkListAPI(Resource):    
    def get(self):
        all_benchmarks = Benchmark.query.all()
        return benchmarks_schema.dump(all_benchmarks)

    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        try:
            data = benchmark_schema.load(json_data)
        except ValidationError as err:
            abort(422, description=err.messages)
        new_benchmark = Benchmark(name=data["name"])
        db.session.add(new_benchmark)
        db.session.commit()
        return benchmark_schema.dump(new_benchmark)

api.add_resource(BenchmarkListAPI, '/benchmarks', endpoint = 'benchmark_list')

class BenchmarkAPI(Resource):
    def get(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        else:
            return benchmark_schema.dump(benchmark)

    # Update benchmark metadata
    def put(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        try:
            data = benchmark_schema.load(json_data)
        except ValidationError as err:
            abort(422, description=err.messages)
        benchmark.name = data.name
        db.session.add(benchmark)
        db.session.commit()
        return benchmark_schema.dump(benchmark)

    # Upload benchmarks
    def post(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        try:
            data = instances_schema.load(json_data)
        except ValidationError as err:
            abort(422, description = err.messages)
        for inst in data:
            instance = Instance(name=inst['name'], body=inst['body'], benchmark=benchmark)
            db.session.add(instance)
        db.session.commit()

    def delete(self, id):
        Benchmark.query.filter_by(Benchmark.id == id).delete()
        db.session.commit()

api.add_resource(BenchmarkAPI, '/benchmarks/<int:id>', endpoint = 'benchmark')

class InstanceListAPI(Resource):
    def get(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        return instance_summary_schema.dump(benchmark.instances.all())
api.add_resource(InstanceListAPI, '/benchmarks/<int:id>/instances', endpoint = 'instance_list')
