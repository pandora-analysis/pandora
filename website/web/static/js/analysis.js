function Analysis(CSRFToken) {
    this.CSRFToken = CSRFToken;
    this.task = null;
    this.refresher = null;
}

Analysis.prototype.refreshStatus = function () {
    // Refresh status alert
    $("#taskStatusAlert").find(".alert").addClass("d-none");
    if (this.task.status === 'DELETED') {
        $("#alertDeleted").removeClass("d-none");
    }
    if (! this.workers_done) {
        $("#alertPending").removeClass("d-none");
    }
    if (this.task.status === "ERROR") {
        $("#alertFailed").removeClass("d-none");
    }

    // Refresh status icon and message
    $("#taskStatusIcon").each(function( index, element ){
      $(this).addClass("d-none");
    })
    $(`.status-flag-${this.task.status.toLowerCase()}`).removeClass("d-none");
    $("#taskStatusMessage").find(".alert").addClass("d-none");
    if (this.task.status === "ERROR") {
        $("#taskStatusMessage").find(".alert-error").removeClass("d-none");
    } else if (this.task.status === "ALERT") {
        $("#taskStatusMessage").find(".alert-danger").removeClass("d-none");
    } else if (this.task.status === "WARN") {
        $("#taskStatusMessage").find(".alert-warning").removeClass("d-none");
    } else if (this.task.status === "CLEAN") {
        $("#taskStatusMessage").find(".alert-success").removeClass("d-none");
    } else {
        $("#taskStatusMessage").find(".alert-info").removeClass("d-none");
    }
};

Analysis.prototype.refreshReports = function () {
    $.each(this.task.reports, function (module, report) {
        // Exit now if report was already finished
        if (! $("#report-"+module).find(".reportStatus")) {
            return;
        }
        // TODO: get html blocks from flask
    });
};

Analysis.prototype.refreshTabs = function () {
    let originTask = this.task;
    let file = this.file;

    if (this.workers_status.preview[0]) {
        $('.preview-wait').each(function(index, element) {
          $(this).addClass("d-none");
        })
        $('.preview-done').each(function(index, element) {
          $(this).removeClass("d-none");
        })

        if (this.workers_status.preview[1] == 'NOTAPPLICABLE') {
            document.getElementById("previews_images").innerHTML = 'Cannot generate a preview for this file format.'
        }
        else {
            previews_url = `/previews/${this.task.uuid}`
            if (this.seed) {
                previews_url = `${previews_url}/seed-${this.seed}`
            }

            fetch(previews_url, {
              method: "GET",
              headers: {
                "X-CSRF-Token": this.CSRFToken
              }
            })
            .then(response => response.text())
            .then(text => {
              document.getElementById("previews_images").innerHTML=text;
            })
        }

    }

    for (const [worker_name, worker_done] of Object.entries(this.workers_status)){
        if (!worker_done[0]) {
            continue;
        };
        if (document.getElementById(worker_name)){
            // Worker results already in page, skip.
            continue;
        }

        worker_url = `/workers_results_html/${this.task.uuid}/${worker_name}`
        if (this.seed) {
            worker_url = `${worker_url}/seed-${this.seed}`
        }
        fetch(worker_url, {
          method: "GET",
          headers: {
            "X-CSRF-Token": this.CSRFToken
          }
        })
        .then(response => response.text())
        .then(text => {
            const workers_results = document.getElementById(`workers_results_${worker_done[1].toLowerCase()}`);
            if (workers_results) {
                workers_results.insertAdjacentHTML('beforeend', text);
            }
            else {
                console.log(`No div for ${worker_done[1]}`);
            }
        })
    }

    if (originTask.observables) {
        // TODO: get html blocks from flask
    }

    if (originTask.extracted_tasks) {
        // TODO: get html blocks from flask
    }

    if (originTask.linked_tasks) {
        // TODO: get html blocks from flask
    }
};

Analysis.prototype.refreshHTML = function () {
    if (this.workers_done && (!this.task.extracted_tasks || this.task.extracted_tasks.every(function(task) { return task.done }))) {
        clearInterval(this.refresher);
    }
    this.refreshStatus();
    this.refreshReports();
    this.refreshTabs();
};

Analysis.prototype.refresh = function (url) {
  fetch(url, {
    method: "POST",
    headers: {
      "X-CSRF-Token": this.CSRFToken
    }
  })
  .then(response => response.json())
  .then(data => {
    if (data.success === false) {
      throw new Error(data.error);
    }
    analysis.task = data.task;
    analysis.seed = data.seed;
    analysis.file = data.file;
    analysis.workers_done = data.workers_done;
    analysis.workers_status = data.workers_status;
    analysis.refreshHTML();
  })
  .catch((error) => {
     clearInterval(analysis.refresher);
     $("#errorJSInner").text("An error has occurred while trying to refresh analysis : " + error);
     $("#errorJS").removeClass("d-none");
  })
};

Analysis.prototype.rescan = function (url) {
    fetch(url, {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.CSRFToken
      }
    })
    .then(response => response.json())
    .then(data => {
      if (data.success === false) {
        throw new Error(data.error);
      }
      window.location = new URL(data.link, location.href);
    })
    .catch((error) => {
      $("#errorJSInner").text("An error has occurred while trying to rescan file : " + error);
      $("#errorJS").removeClass("d-none");
    })
};

Analysis.prototype.notify = function (url) {
    fetch(url, {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.CSRFToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({email: $("#email").val(), message: $("#message").val()})
    })
    .then(response => response.json())
    .then(data => {
      if (data.success === false) {
        throw new Error(data.error);
      }
      $("#notifySuccess").removeClass("d-none");
      $("#notifyError").addClass("d-none");
      $("#notifyErrorReason").text("");
      $("#notifySubmit").attr("data-bs-dismiss", "modal").text("Done");
    })
    .catch((error) => {
      $("#notifyError").removeClass("d-none");
      $("#notifySuccess").addClass("d-none");
      $("#notifyErrorReason").text(error);
      $("#notifySubmit").attr("type", "submit").text("Retry");
    });
    return false;
};

Analysis.prototype.share = function (url) {
    fetch(url, {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.CSRFToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({validity: $("#shareDays").val() + "d"})
    })
    .then(response => response.json())
    .then(data => {
      if (data.success === false) {
          throw new Error(data.error);
      }
      $("#shareLink").attr("href", new URL(data.link, location.href));
      if (data.lifetime > 0) {
          $("#sharePeriod").text("during " + parseInt(data.lifetime / (3600*24)) + " days");
      } else {
          $("#sharePeriod").text("permanently");
      }
      $("#shareSuccess").removeClass("d-none");
      $("#closeBuild").removeClass("d-none");
      $("#shareError").addClass("d-none");
      $("#shareErrorReason").text("");
      $("#shareBuild").addClass("d-none");
    })
    .catch((error) => {
      $("#shareError").removeClass("d-none");
      $("#shareSuccess").addClass("d-none");
      $("#shareErrorReason").text(error);
      $("#shareBuild").attr("type", "submit").text("Retry");
    });
    return false;
};

Analysis.prototype.deleteFile = function (url) {
    if (! confirm("Are you sure you want to delete this file ? That action is irreversible !")) {
        return false;
    }
    fetch(url, {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.CSRFToken
      }
    })
    .then(response => response.json())
    .then(data => {
      if (data.success === false) {
        throw new Error(data.error);
      }
      window.location.reload();
    })
    .catch((error) => {
      alert("An error has occurred while removing file : " + error);
    })
    return false;
};
