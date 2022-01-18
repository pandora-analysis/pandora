function Role(CSRFToken, updateURL, reloadURL) {
    this.CSRFToken = CSRFToken;
    this.updateURL = updateURL;
    this.reloadURL = reloadURL;
}

Role.prototype.update = function (roleName, permission, value) {
    fetch(this.updateURL, {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.CSRFToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({role_name: roleName, permission: permission, value: value})
    })
    .then(response => response.json())
    .then(data => {
      if (data.success === false) {
        throw new Error(data.error);
      }
      $(`#true-${roleName}-${permission}`).toggleClass("d-none");
      $(`#false-${roleName}-${permission}`).toggleClass("d-none");
    })
    .catch((error) => {
      alert("An error has occurred while changing role permission : " + error);
    });
}

Role.prototype.reload = function () {
    if (!confirm("All the roles will be removed and re-created, are you sure that your config file is correctly formatted ?")) {
        return false;
    }
    fetch(this.reloadURL, {
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
      alert("An error has occurred while reloading roles from config file : " + error);
    });
}
