
# Tutor Site

## Overview

The goal of this project is to help students find other students to tutor them.  Finding a private tutor can be very difficult
and expensive.  With tutor site, students either find a tutor in a given subject or offer their tutoring services to others.

## Running the site

1. Clone the project to your server/virtual machine

2. Register your app with google and facebook to allow OAuth authentication.
	
	- With google, save the provided json file as `client_secrets.json` in the main directory

	- With facebook, create a file called `fb_client_secrets.json` and save your app_id and app_secrete in it so that it looks as follows:

			{
			  "web": {
			    "app_id": "PASTE APP ID HERE",
			    "app_secret": "PASTE APP SECRETE HERE"
			  }
			}

2. ssh into the server/machine

3. Set up the database by running `python db_setup.py`

	- Optionally, you can add some basic data to the site by running `python import_data.py`

4. Start hosting the site by running `python main.py`

5. The site can now by accessed via a web browser at `http://localhost:5000/`

## Files

* `main.py` contains the bulk of the code including all the handlers.

* `import_data.py` Contains some basic info that can be loaded into the database after the database has been created.  It should not be run more than once.

* `templates` contains all of the html for the pages.

	* `base.html` contains the common header and footer for all pages.

* `static` contains all the static files for the project, including the css, js, and images.

	* `pictures` If a user decides to upload a profile picture, it is stored in this folder, organized by their user ID.

