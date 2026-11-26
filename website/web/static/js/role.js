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
      pdrAlert("The permission could not be changed: " + error, {title: "Change failed"});
    });
}

Role.prototype.reload = async function () {
    if (!(await pdrConfirm("All roles will be deleted and re-created from config/roles.yml. Changes made on this page will be lost. Check that the file is correctly formatted first.",
                           {title: "Reload the roles?", confirmLabel: "Reload the roles", danger: true}))) {
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
      pdrAlert("The roles could not be reloaded: " + error, {title: "Reload failed"});
    });
}
