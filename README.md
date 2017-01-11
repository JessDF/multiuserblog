# multiuserblog
Udacity Full Stack Developer Nanodegree - Project 3: Multi User Blog

    This application is hosted at the following link:

However, if you want to run it on a local server here are the steps:

    1. Download the code.

    2. You must install google app engine. For more information: https://cloud.google.com/appengine/

    3. After it is installed, use the Google Cloud SDK shell. Go to the directory the code is installed.

To depoloy to cloud:

    1. gcloud app deply will install the code to your own version of the app engine.

To test locally:

    1. dev_appserver.py .
    2. then you can use your browser to view locally at: http://localhost:8080  // 8080 may change 
    // this depends on how many applications you run.

It uses jinja2 templates to serve the web pages. Data is stored with google app engine. 
