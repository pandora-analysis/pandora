let chart = null;
let selectedDate = "";
let onErrorTrigger;

function OnPeriodChange(){
    const selectElement = document.querySelector('#period');
    selectElement.addEventListener('change', (event) => {
        let minViewMode = 2;
        let format = "yyyy"
        if(selectElement.value == "month"){
            minViewMode = 1;
             format = "mm/yyyy"
        }else if(selectElement.value == "day"){
            minViewMode = 0;
            format ="dd/mm/yyyy"
        }else if (selectElement.value == "week") {
            minViewMode = 0;
            format ="dd/mm/yyyy"
        }

        // Destroy previous datepicker
        $('#stats-container #date-picker').datepicker('destroy');
        // Re-int with new options
        initDatePicker(minViewMode, format)
    });
}

function getEndDate(){
    const today = new Date()
    const tomorrow = new Date(today)
    tomorrow.setDate(today.getDate() + 1)
    return tomorrow.toISOString()
}

function initDatePicker(minViewMode,format) {
    $('#stats-container #date-picker').datepicker({
        format: format,
        endDate: getEndDate(),
        startView: 2,
        minViewMode: minViewMode,
        maxViewMode: 2,
        orientation: "bottom auto",
        calendarWeeks: true,
        autoclose: true,
        setDate: new Date(),
    }).on('hide',  (ev) => {
        const period = $("#period").val()
        if(ev.date) {
            const dateSel = new Date(ev.date)
            if (period == "week") {
                const mDate = moment(dateSel);
                $('#date-picker').val(`Week ${mDate.isoWeek()} of ${mDate.year()}`);
                updateData(chart, `${mDate.isoWeek()}/${mDate.year()}`);
                return
            }
            updateData(chart);
            selectedDate = $("#date-picker").val()
        }else {
            $("#date-picker").val(selectedDate)
        }
    })
    const today = moment(new Date())
    const period = $("#period").val()
    if(period == "week"){
        $('#date-picker').val(`Week ${today.isoWeek()} of ${today.year()}`);
        updateData(chart, `${today.isoWeek()}/${today.year()}`);
    } else{
        $('#date-picker').val(today.format(format.toUpperCase()));
        updateData(chart);
    }
    selectedDate = $("#date-picker").val()
}


function initChart(data) {
    'use strict'

    // Graphs
    const ctx = document.getElementById('submit-chart')

    // eslint-disable-next-line no-unused-vars
     chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.values,
                lineTension: 0.1,
                backgroundColor: 'transparent',
                borderColor: '#009697',
                borderWidth: 4,
                pointBackgroundColor: '#009697'
            }]
        }
    })
}

function updateChart(labels, values){
    chart.data.labels = labels
    chart.data.datasets[0].data = values
    chart.update()
}

function removeData(chart) {
    chart.data.labels = []
    chart.data.datasets[0].data = []
    chart.update();
}


function updateData(chart, selected){
    const period = $("#period").val()
    if(!selected) {
        selected =  $('#date-picker').val()
    }
    getSubmit(period, selected)
    getInfos(period, selected)

}

function updateSubmitInfos(infos){
    const tbody = $('#submit-infos .table tbody')
    $("#submit-infos .table tbody tr").remove();
    Object.keys(infos).forEach(key => {
        if(key != "total") {
            const newRowContent = `<tr><td>${key}</td><td>${infos[key]}</td></tr>`
            tbody.append(newRowContent);
        }
    })
    if(infos.total != undefined){
        tbody.append(`<tr><td><B>Total</B></td><td><b>${infos.total}</b></td></tr>`);
    }
}

function updateFilesInfos(infos){
    const tbody = $('#files-info .table tbody')
    $("#files-info .table tbody tr").remove();
    Object.keys(infos).forEach(key => {
        if(key != "total") {
            const newRowContent = `<tr><td>${key}</td><td>${infos[key]}</td></tr>`
            tbody.append(newRowContent);
        }
    })
    if(infos.total  != undefined){
        tbody.append(`<tr><td><B>Total</B></td><td><b>${infos.total}</b></td></tr>`);
    }
}

function updateSizeInfos(infos){
    const tr = $('#files-size-info .table tbody tr')
    $("#files-size-info .table tbody tr td").remove();
    tr.append(`<td>${infos.min}</td>`);
    tr.append(`<td>${infos.max}</td>`);
    tr.append(`<td>${infos.avg}</td>`);
    $('#type_table').DataTable({
      order: [[1, 'desc']],
    });
}

function updateInterval(start, end){
    $('#interval-info .start-date').text(start)
    $('#interval-info .end-date').text(end)
}

function updateMetrics(metrics){
    const ratioDiv = $("#alert-ratio")
    const ratioMetric = $("#alert-ratio .metric")
    const totalMetrics = $("#total-submits .metric")
    const maliciousMetric = $("#malicious-submits .metric")
    const suspiciousMetric = $("#suspicious-submits .metric")
    const overwrittenMetric = $("#overwritten-submits .metric")
    const cleanMetric = $("#clean-submits .metric")
    ratioDiv.removeClass()

    const nbf = Intl.NumberFormat("en",{ notation: "compact" , compactDisplay: "short" })
    ratioMetric.text(nbf.format(metrics.alert_ratio))
    maliciousMetric.text(nbf.format(metrics.malicious))
    suspiciousMetric.text(nbf.format(metrics.suspicious))
    overwrittenMetric.text(nbf.format(metrics.overwritten))
    cleanMetric.text(nbf.format(metrics.clean))
    totalMetrics.text(nbf.format(metrics.submits))

    if(metrics.alert_ratio > 80){
        ratioDiv.addClass("ratio-alert")
    }else if (metrics.alert_ratio > 50){
        ratioDiv.addClass("ratio-warn")
    }else{
        ratioDiv.addClass("ratio-okay")
    }
}

function previousDate(){
    const period = $("#period").val()
    let selected =  $('#date-picker').val()
    const today = moment()
    let toShow = selected
    if(period == "year"){
        const pattern = "YYYY"
        let mDate = moment(selected,pattern)
        if(mDate < today){
            enableNext()
        }
        mDate = mDate.subtract(1, 'year')
        selected = mDate.format(pattern)
        toShow = selected
    }else if(period == "month"){
        const pattern = "MM/YYYY"
        let mDate = moment(selected,pattern)
        if(mDate < today){
            enableNext()
        }
        mDate = mDate.subtract(1, 'months')
        selected = mDate.format(pattern)
        toShow = selected
    }else if(period == "week"){
        const pattern = "Week WW of YYYY"
        const week = selected.split(" ")[1]
        const year = selected.split(" ")[3]
        if(week == 53){
            toShow = `Week 52 of ${year}`
            selected = `52/${year}`
        }else{
            let mDate = moment(selected,pattern)
            if(mDate < today){
                enableNext()
            }
            mDate = mDate.subtract(7,"days")
            toShow = `Week ${mDate.isoWeek()} of ${mDate.year()}`
            selected = mDate.format("WW/YYYY")
        }
    }else if(period == "day"){
        let pattern = "DD/MM/YYYY"
        let mDate = moment(selected,pattern)
        if(mDate < today){
            enableNext()
        }
        mDate = mDate.subtract(1, 'days')
        selected = mDate.format(pattern)
        toShow = selected
    }
    $('#date-picker').val(toShow)
    updateData(chart, selected)
}


function nextDate(){
    const period = $("#period").val()
    let selected =  $('#date-picker').val()
    let toShow = ""
    const today = moment()
    if(period == "year"){
        const pattern = "YYYY"
        const mDate = moment(selected,pattern).add(1, 'year')
        if(mDate < today) {
            selected = mDate.format(pattern)
            toShow = selected
        }
        if (mDate.add(1,"year") > today){
            disableNext()
        }
    }else if(period == "month"){
        const pattern = "MM/YYYY"
        const mDate = moment(selected,pattern).add(1, 'month')
        if(mDate < today) {
            selected = mDate.format(pattern)
            toShow = selected
        }
        if (mDate.add(1,"month") > today){
            disableNext()
        }
    }else if(period == "week"){
        const pattern = "Week WW of YYYY"
        const mDate =  moment(selected,pattern).add(1,"week")
        if(mDate < today) {
            toShow = `Week ${mDate.isoWeek()} of ${mDate.year()}`
            selected = mDate.format("WW/YYYY")
        }
        if (mDate.add(1,"week") > today){
            disableNext()
        }
    }else if(period == "day"){
        let pattern = "DD/MM/YYYY"
        const mDate = moment(selected,pattern).add(1, 'day')
        if(mDate < today) {
            selected = mDate.format(pattern)
            toShow = selected
        }
        if (mDate.add(1,"day") > today){
            disableNext()
        }
    }
    if(toShow) {
        $('#date-picker').val(toShow)
        updateData(chart, selected)
    }
}

function disableNext(){
    $("#next-date").addClass("disabled")
}
function enableNext(){
    $("#next-date").removeClass("disabled");
}


function onError(error){
    onErrorTrigger = true;
    $("#stats-container").hide()
    $("#error-stats-container .error").text(error)
    $("#error-stats-container").show()
}

initDatePicker(2,"yyyy");
OnPeriodChange();
disableNext()
