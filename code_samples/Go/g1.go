// server.go
// Go example with insecure patterns for learning
// Issues: template injection/xss, path traversal, unsafe JSON handling

package main

import (
    "encoding/json"
    "fmt"
    "html/template"
    "io/ioutil"
    "log"
    "net/http"
    "os"
)

const port = ":9090"

func profileHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if name == "" {
        name = "guest"
    }
    // Unsafe: using text/template or not escaping user input can cause XSS
    tpl := "<html><body><h1>User: {{.}}</h1></body></html>"
    t := template.Must(template.New("user").Parse(tpl))
    t.Execute(w, name) // if template uses html/template this is generally okay, but if tpl is built dynamically it can be risky
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
    file := r.URL.Query().Get("file")
    if file == "" {
        file = "index.html"
    }
    // path traversal vulnerability: no normalization
    data, err := ioutil.ReadFile("./public/" + file)
    if err != nil {
        http.NotFound(w, r)
        return
    }
    w.Write(data)
}

func jsonHandler(w http.ResponseWriter, r *http.Request) {
    body, _ := ioutil.ReadAll(r.Body)
    var v interface{}
    // decoding into interface{} without schema validation
    json.Unmarshal(body, &v)
    fmt.Fprintf(w, "Received: %+v", v)
}

func main() {
    if _, err := os.Stat("./public"); os.IsNotExist(err) {
        os.Mkdir("./public", 0755)
    }

    http.HandleFunc("/profile", profileHandler)
    http.HandleFunc("/file", fileHandler)
    http.HandleFunc("/json", jsonHandler)
    log.Printf("Listening on %s", port)
    http.ListenAndServe(port, nil)
}
