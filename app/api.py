from flask import Flask, request
from flask_restful import Api, Resource, abort
from flask_marshmallow import Marshmallow
from marshmallow import ValidationError

from app import app, db
from app.models import Benchmark

api = Api(app)
ma = Marshmallow(app)

class BenchmarkListEntrySchema(ma.Schema):
    id = ma.Int(dump_only=True)
    name = ma.Str()

benchmark_schema = BenchmarkListEntrySchema()
benchmarks_schema = BenchmarkListEntrySchema(many=True)

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
        # It's an error if a benchmark with this name already exists
        existing_benchmark = Benchmark.query.filter_by(name=data["name"]).first()
        if existing_benchmark is not None:
            abort(409, description="A benchmark with that name already exists")
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

api.add_resource(BenchmarkAPI, '/benchmarks/<int:id>', endpoint = 'benchmark')
