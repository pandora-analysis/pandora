function Observable(CSRFToken, insertURL, updateURL) {
    this.CSRFToken = CSRFToken;
    this.insertURL = insertURL;
    this.updateURL = updateURL;
}

Observable.prototype.insert = function () {
    $("#insertSubmit").text("Adding observable...");
    $("#insertSubmit").attr("type", "button");
    fetch(this.insertURL, {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.CSRFToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({address: $("#insertAddress").val(), allowlist: $("#insertallowlist").val()})
    })
    .then(response => response.json())
    .then(data => {
      cellType = $("<td>").text(data.type_observable);
      cellAddress = $("<td>").html(`<b>${data.address}</b>`);
      cellallowlist = $("<td>").addClass("text-left");
      spanOkay = $("<span>").attr("id", `okay-${data.id}`).attr("onclick", `observable.update(${data.id}, 0)`);
      spanOkay.attr("style", "width:150px").addClass("img-thumbnail small-status-flag status-flag-clean");
      spanOkay.html('safe');
      spanWarn = $("<span>").attr("id", `warn-${data.id}`).attr("onclick", `observable.update(${data.id}, 1)`);
      spanWarn.attr("style", "width:150px").addClass("img-thumbnail small-status-flag status-flag-warn");
      spanWarn.html('suspicious');
      if (data.allowlist) {
          spanWarn.addClass("d-none");
      } else {
          spanOkay.addClass("d-none");
      }
      cellallowlist.append(spanOkay, spanWarn)
      rowObservable = $("<tr>").attr("id", `row-${data.id}`).addClass("row-observable");
      rowObservable.append(cellType, cellAddress, cellallowlist);
      rowObservable.insertBefore($(".row-observable").eq(0));
      $("#insertSubmit").text("Add observable");
      $("#insertSubmit").attr("type", "submit");
      $("#insertError").addClass("d-none");
    })
    .catch((error) => {
      $("#insertError").removeClass("d-none");
      $("#insertErrorInner").text(error);
      $("#insertSubmit").text("Retry");
      $("#insertSubmit").attr("type", "submit");
    });
    return false;
}

Observable.prototype.update = function (observableId, allowlist) {
    fetch(this.updateURL, {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.CSRFToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({address: observableId, allowlist: allowlist})
    })
    .then(response => response.json())
    .then(data => {
      if (data.success === false) {
        throw new Error(data.error);
      }
      $(`#okay-${observableId}`).toggleClass("d-none");
      $(`#warn-${observableId}`).toggleClass("d-none");
    })
    .catch((error) => {
      alert("An error has occurred while changing observable allowlist : " + error);
    });
}
