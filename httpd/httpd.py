import os
import asyncio

try:
    from aiohttp import web
except ImportError:
    web = None


class Httpd(object):

    def __init__(self, ctx):
        if not web:
            print('httpd is specified in conf but aiohttp not available')
            return
        self.ctx = ctx
        self._init_aiohttp(ctx)
        self._setup_routes(ctx)
        self._run_app(ctx)

    def _init_aiohttp(self, ctx):
        app = web.Application()
        app['ctx'] = self.ctx
        self.ctx['app'] = app

    def _run_app(self, ctx):
        loop = asyncio.get_event_loop()
        handler = ctx['app'].make_handler()
        f = loop.create_server(handler, '0.0.0.0', 8080)
        srv = loop.run_until_complete(f)
        print('serving on', srv.sockets[0].getsockname())

    async def handler_index(self, request):
        data = '''
<!doctype html>
<html>
<head>
  <script type="text/javascript" src="static/js/vis.min.js"></script>
  <script type="text/javascript" src="static/js/script.js"></script>
  <link href="static/css/vis.min.css" rel="stylesheet" type="text/css" />
  <link href="static/css/style.css" rel="stylesheet" type="text/css" />
</head>
<body>
<div id="mynetwork"></div>
</body>
</html>
        '''
        data = str.encode(data)
        return web.Response(body=data, content_type='text/html')


    def _setup_routes(self, ctx):
        absdir = os.path.dirname(os.path.realpath(__file__))
        app_path = os.path.join(absdir, 'www', 'static')
        ctx['app'].router.add_get('/', self.handler_index)
        ctx['app'].router.add_static('/static', app_path, show_index=True)



