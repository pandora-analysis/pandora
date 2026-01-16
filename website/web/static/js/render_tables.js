"use strict";

function render_datetime_with_tz(data) {
    if(! isNaN(data)){
        data = parseInt(data);
    }
    const date = new Date(data);
    return `${date.getFullYear()}-${(date.getMonth() + 1).toString().padStart(2, "0")}-${date.getDate().toString().padStart(2, "0")} ${date.toTimeString()}`;
};

DataTable.render.datetime_with_tz = function () {
    return function ( data, type, row ) {
        if ( type === 'display' || type === 'filter') {
            return render_datetime_with_tz(data);
        }
        return data;
    };
}

function renderTables() {
    if (document.getElementById('TasksTable')) {
        let csrf_token = document.getElementById('TasksTable').dataset.csrf;
        new DataTable('#TasksTable', {
          processing: true,
          serverSide: true,
          retrieve: true,
          ordering: false,
          // Note: search is broken at this stage and requires a proper intexer to work again.
          searching: false,
          order: [[ 2, "desc" ]],
          ajax: {
            url: `/tables/tasksTable/${window.location.search}`,
            type: 'POST',
            headers: {"X-CSRF-Token" : csrf_token}
          },
          columns : [
              { data: 'id', width: '10%' },
              { data: 'owner', width: '5%' },
              { data: 'date', width: '15%', render: DataTable.render.datetime_with_tz() },
              { data: {_: 'status.display', filter: 'status.filter'}, width: '5%' },
              { data: {_: 'name.display', filter: 'name.filter'}, width: '40%' },
              { data: 'sha256', width: '15%' },
              { data: {_: 'buttons.display', filter: 'buttons.filter'}, width: '10%' }
          ],
        })
    }
}

document.addEventListener("DOMContentLoaded", () => {
    renderTables();
});
