#!venv/bin/python3
from config import *
from functions import *
import concurrent.futures
from elasticsearch import Elasticsearch
import json, os, time, ssl, urllib3, warnings
from tornado import concurrent, gen, httpserver, ioloop, log, web, iostream
from elasticsearch import NotFoundError, RequestError
os.system("openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -subj '/CN=mylocalhost'")
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
warnings.filterwarnings("ignore", category=Warning, message=".*verify_certs=False is insecure.*")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def execute_query(con, query, fetch_one=False, fetch_all=False):
    """Executes a query and returns results if required."""
    cur = con.cursor()  # Create cursor without "with"
    
    cur.execute(query)
    
    if fetch_one:
        result = cur.fetchone()
    elif fetch_all:
        result = cur.fetchall()
    else:
        result = None

    con.commit()  # Commit changes if needed
    cur.close()   # Manually close the cursor (important for SQLite)

    return result

def db_count_urls(db):
    try:
        res = db.search(index=URLS_INDEX, body={"track_total_hits": True, "query": {"match_all": {}}})
        return res["hits"]["total"]["value"]
    except Exception as e:
        print("[Elasticsearch] Error counting URLs:", e)
        return 0

def db_get_unique_domain_count(db):
    try:
        query = {
            "size": 0,
            "aggs": {
                "unique_hosts": {
                    "cardinality": {
                        "field": "host"
                    }
                }
            }
        }
        res = db.search(index=URLS_INDEX, body=query)
        return res["aggregations"]["unique_hosts"]["value"]
    except Exception as e:
        print("[Elasticsearch] Error counting unique domains:", e)
        return 0

def db_get_visit_count(db):
    try:
        query = {
            "query": {
                "term": {
                    "visited": True
                }
            },
            "track_total_hits": True
        }
        res = db.search(index=URLS_INDEX, body=query)
        return res["hits"]["total"]["value"]
    except Exception as e:
        print("[Elasticsearch] Error counting visited URLs:", e)
        return 0

def db_get_email_count(db):
    try:
        query = {
            "size": 0,
            "aggs": {
                "unique_emails": {
                    "cardinality": {
                        "field": "email"
                    }
                }
            }
        }
        res = db.search(index=EMAILS_INDEX, body=query)
        return res["aggregations"]["unique_emails"]["value"]
    except Exception as e:
        print("[Elasticsearch] Error counting unique emails:", e)
        return 0

def db_get_content_type_count(db):
    try:
        query = {
            "size": 0,
            "aggs": {
                "top_content_types": {
                    "terms": {
                        "field": "content_type.keyword",  # assuming 'content_type' is a text field with a keyword subfield
                        "size": 10,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            }
        }
        res = db.search(index=URLS_INDEX, body=query)
        return [(bucket["key"], bucket["doc_count"]) for bucket in res["aggregations"]["top_content_types"]["buckets"]]
    except Exception as e:
        print("[Elasticsearch] Error getting content type counts:", e)
        return []

def db_get_top_domain(db):
    try:
        query = {
            "size": 0,
            "aggs": {
                "top_hosts": {
                    "terms": {
                        "field": "host",
                        "size": 10,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            }
        }
        res = db.search(index=URLS_INDEX, body=query)
        return [(bucket["key"], bucket["doc_count"]) for bucket in res["aggregations"]["top_hosts"]["buckets"]]
    except Exception as e:
        print("[Elasticsearch] Error getting top domains:", e)
        return []


def db_get_porn_domains(db):
    try:
        query = {
            "size": 0,  # We don’t need actual docs, just the aggregation
            "query": {
                "bool": {
                    "must": [
                        {"range": {"resolution": {"gte": 224 * 224}}},
                        {"exists": {"field": "isnsfw"}}
                    ]
                }
            },
            "aggs": {
                "group_by_parent": {
                    "terms": {
                        "field": "parent_host",
                        "size": 10000,  # Adjust if needed
                        "min_doc_count": 5  # At least 5 docs to meet c > 4
                    },
                    "aggs": {
                        "avg_isnsfw": {"avg": {"field": "isnsfw"}},
                        "bucket_filter": {
                            "bucket_selector": {
                                "buckets_path": {
                                    "avgNSFW": "avg_isnsfw",
                                    "count": "_count"
                                },
                                "script": "params.avgNSFW > 0.3"
                            }
                        }
                    }
                }
            }
        }

        res = db.search(index=URLS_INDEX, body=query)
        results = []

        for bucket in res["aggregations"]["group_by_parent"]["buckets"]:
            parent_host = bucket["key"]
            avg_isnsfw = bucket["avg_isnsfw"]["value"]
            count = bucket["doc_count"]
            results.append((avg_isnsfw, parent_host, count))

        # Sort by average NSFW score (ascending)
        results.sort(key=lambda x: x[0])
        return results

    except Exception as e:
        print("[Elasticsearch] Error getting porn domains:", e)
        return []


def db_get_porn_urls(db):
    try:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"resolution": {"gte": 224 * 224}}},
                        {"exists": {"field": "isnsfw"}}
                    ]
                }
            },
            "sort": [{"isnsfw": {"order": "desc"}}],
            "size": 10,
            "_source": ["isnsfw", "url"]
        }

        res = db.search(index=URLS_INDEX, body=query)
        return [(hit["_source"]["isnsfw"], hit["_source"]["url"]) for hit in res["hits"]["hits"]]

    except Exception as e:
        print("[Elasticsearch] Error getting porn URLs:", e)
        return []


def db_get_open_dir(db):
    try:
        query = {
            "query": {
                "term": {
                    "isopendir": True  # Assuming `isopendir` is stored as a boolean
                }
            },
            "_source": ["url"],
            "size": 10000  # Adjust as needed or implement scroll for large datasets
        }
        res = db.search(index=URLS_INDEX, body=query)
        return [hit["_source"]["url"] for hit in res["hits"]["hits"] if "url" in hit["_source"]]
    except Exception as e:
        print("[Elasticsearch] Error getting open directories:", e)
        return []


def db_get_all_hosts(db):
    query = {
        "size": 10000,
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "host"}},
                    {"exists": {"field": "parent_host"}}
                ]
            }
        },
        "_source": ["host", "parent_host"]
    }
    try:
        res = db.search(index=URLS_INDEX, body=query)
        hits = res.get("hits", {}).get("hits", [])
        hosts = set()
        for hit in hits:
            src = hit.get("_source", {})
            if src.get("host"):
                hosts.add(src["host"])
            if src.get("parent_host"):
                hosts.add(src["parent_host"])
        return list(hosts)
    except Exception as e:
        print("[Elasticsearch] Error retrieving hosts:", e)
        return []


def db_get_all_relations(con):
    if not con:
        print("Elasticsearch connection not available.")
        return []

    try:
        # Define the query
        query_body = {
            "_source": ["host", "parent_host"],
            "query": {
                "bool": {
                    "must": [
                        { "exists": { "field": "host" } },
                        { "exists": { "field": "parent_host" } },
                        { "script": {  # filter out empty strings
                            "script": {
                                "source": "doc['host'].value.length() > 0 && doc['parent_host'].value.length() > 0",
                                "lang": "painless"
                            }
                        }}
                    ]
                }
            },
            "size": 10000  # max documents per batch (Elasticsearch default max)
        }

        # Initial search
        result = con.search(index=URLS_INDEX, body=query_body, scroll="2m")
        scroll_id = result["_scroll_id"]
        hits = result["hits"]["hits"]

        # Collect all results
        relations = [
            (doc["_source"]["parent_host"], doc["_source"]["host"])
            for doc in hits
        ]

        # Scroll if more results exist
        while len(hits) > 0:
            result = con.scroll(scroll_id=scroll_id, scroll="2m")
            hits = result["hits"]["hits"]
            relations.extend([
                (doc["_source"]["parent_host"], doc["_source"]["host"])
                for doc in hits
            ])

        # Return as list of tuples
        return relations

    except Exception as e:
        print("[Elasticsearch] Error retrieving relations:", e)
        return []


def update_data():
    db = DatabaseConnection()
    ensure_database_created=get_random_unvisited_domains(db)
    network={}
    network['nodes']=[]
    network['links']=[]
    links=set()
    for host in db_get_all_hosts(db):
        group='.'+str(host)
        group=group.split('.')[-GROUP_DOMAIN_LEVEL]
        network['nodes'].append({'id':host,'group':group})
    for relation in db_get_all_relations(db):
        links.add(frozenset([relation[0],relation[1]]))
    for link in links:
        y=list(link)
        if len(y) == 2:
            network['links'].append({'source':y[0],'target':y[1],'value':1})
    with open('network.json', 'w') as f:
        json.dump(network, f)
    f = open('network.html', 'w')
    f.write('''\
            <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dynamic Force Graph</title>
  <style>
    body { margin: 0; }
  </style>
  <script src="//unpkg.com/force-graph"></script>
</head>
<body>
  <div id="graph"></div>
  <button id="toggleButton">Stop/Restart</button> <!-- Add a button -->
  <script>
    let savedNodePositions = {}; // Object to store node positions
    let intervalId; // Variable to store interval ID

    // Function to fetch JSON data and render graph
    function renderGraph() {
      fetch('network.json')
        .then(res => res.json())
        .then(data => {
          // Check if the graph is already initialized
          if (window.Graph) {
            // Save current node positions
            window.Graph.graphData().nodes.forEach(node => {
              savedNodePositions[node.id] = { x: node.x, y: node.y };
            });
            window.Graph.graphData(data);
            // Apply saved node positions
            window.Graph.graphData().nodes.forEach(node => {
              if (savedNodePositions[node.id]) {
                node.x = savedNodePositions[node.id].x;
                node.y = savedNodePositions[node.id].y;
              }
            });
            window.Graph.refresh(); // Refresh the graph to apply changes
          } else {
            window.Graph = ForceGraph()(document.getElementById('graph'))
              .graphData(data)
              .nodeId('id')
              .nodeVal('val')
              .nodeLabel('id')
              .nodeAutoColorBy('group')
              .linkSource('source')
              .linkTarget('target');
          }
        })
        .catch(error => {
          console.error('Error fetching JSON data:', error);
        });
    }

    // Initial render of the graph
    renderGraph();

    // Function to start checking for updates
    function startCheckingForUpdates() {
      intervalId = setInterval(() => {
        renderGraph();
      }, 5000); // Adjust the interval as needed (e.g., every 5 seconds)
    }

    // Start checking for updates
    startCheckingForUpdates();

    // Function to stop checking for updates
    function stopCheckingForUpdates() {
      clearInterval(intervalId);
    }

    // Event listener for the toggle button
    document.getElementById('toggleButton').addEventListener('click', function() {
      if (intervalId) {
        // If intervalId is set, stop checking for updates
        stopCheckingForUpdates();
        intervalId = null;
      } else {
        // If intervalId is not set, start checking for updates
        startCheckingForUpdates();
      }
    });
  </script>
    ''')
    f.write('''
    <br>Total urls/visited: {}/{}<br>
    <br>Domain count: {}<br>
    Total emails: {}<br>
    Top Urls:<br>
    <table>'''.format(db_count_urls(db),db_get_visit_count(db),db_get_unique_domain_count(db),db_get_email_count(db)))
    for line in db_get_top_domain(db):
        f.write('<tr><td>{}</td><td>{}</td></tr>'.format(line[0],line[1]))
    f.write('</table><br>Top Content-Type:<br><table>')
    for line in db_get_content_type_count(db):
        f.write('<tr><td>{}</td><td>{}</td></tr>'.format(line[0],line[1]))
    f.write('</table><br>Open directories:<br><table>')
    for line in db_get_open_dir(db):
        f.write('<tr><td>{}</td></tr>'.format(line[0]))
    f.write('</table><br>Top porn domains:<br><table>')
    for line in db_get_porn_domains(db):
        f.write('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(line[0],line[1],line[2]))
    f.write('</table><br>Top porn urls:<br><table>')
    for line in db_get_porn_urls(db):
        f.write('<tr><td>{}</td><td><a href={}>{}</a></td></tr>'.format(line[0],line[1],line[1]))
    f.write('''\
    </table>
    </body>
    </html>
    '''.format(db_count_urls(db)))
    f.close()

class MainHandler(web.RequestHandler):
    def get(self):
        with open("network.html", "r") as file:
            html_content = file.read()
        self.set_header("Content-Type", "text/html")
        self.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.set_header("Pragma", "no-cache")
        self.set_header("Expires", "0")
        self.write(html_content)

def periodic_task():
    update_data()

def make_app():
    return web.Application([
        (r"/", MainHandler),
        (r"/network.html", web.StaticFileHandler, {"path": os.getcwd()}), 
        (r"/(.*)", web.StaticFileHandler, {"path": os.getcwd()})
    ],
    debug=False)

def main():
    app = make_app()
    periodic_callback = ioloop.PeriodicCallback(periodic_task, 5000)
    periodic_callback.start()
    server = httpserver.HTTPServer(app, ssl_options={
        "certfile": "cert.pem",  
        "keyfile": "key.pem", 
    })
    server.listen(EMBED_PORT)  # HTTPS default port
    ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()
