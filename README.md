# multiuserblog
Udacity Full Stack Developer Nanodegree - Project 3: Multi User Blog

    This application is hosted at the following link: https://finaludacity-155121.appspot.com/
    
    Application will redirct you to a sign up page - if you don't want to sign up and wish to 
    only view the blog go to this link:  https://finaludacity-155121.appspot.com/blog

However, if you want to run it on a local server here are the steps:

    1. Download the code.

    2. You must install google app engine. For more information: https://cloud.google.com/appengine/

    3. After it is installed, use the Google Cloud SDK shell. Go to the directory the code is installed.

To depoloy to cloud:

    1. gcloud app deploy will install the code to your own version of the app engine.

To test locally:

    1. dev_appserver.py .
    2. then you can use your browser to view locally at: http://localhost:8080  // 8080 may change 
    // this depends on how many applications you run.

It uses jinja2 templates to serve the web pages. Data is stored with google app engine. 
