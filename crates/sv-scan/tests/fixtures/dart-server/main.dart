import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;

Response handler(Request request) => Response.ok('notes');

void main() async {
  await io.serve(handler, '127.0.0.1', 8080);
}
