let submitLoading = true
let submitEnding = false
let statsLoading = false
let statsEnding = false

function getSubmit(period, selected){
    const url = formatUrl("/api/stats/submit", period, selected)
    //Fetch data
    $.ajax({
        url: url,
        dataType:"json",
        async: true,
        success: (data) => {
            if(data.success != undefined && !data.success){
                onError(data.error)
            }
            updateInterval(data.date_start, data.date_end)

            let labels = {}
            let values = {}
            if(period == "year"){
                labels = data.sub_months.map(el => `${el[0]}/${selected}`)
                values = data.sub_months.map(el => el[1])
            }else if(period == "month"){
                labels = data.sub_weeks.map(el => `Day ${el[0]}`)
                values = data.sub_weeks.map(el => el[1])
            }else if(period == "week"){
                labels = data.sub_days.map(el => moment.weekdays()[el[0]])
                values = data.sub_days.map(el => el[1])
            }else if(period == "day"){
                labels = data.sub_hours.map(el => el[0])
                values = data.sub_hours.map(el => el[1])
            }

            if (chart == null){
                initChart(data)
            }
            updateChart(labels, values)
        },
        error: function(XMLHttpRequest, textStatus, errorThrown) {
            const data = XMLHttpRequest.responseJSON
            if(data && data.success != undefined && !data.success){
                onError(data.error)
            }else {
                onError(`Code ${XMLHttpRequest.status}: ${XMLHttpRequest.statusText}`)
            }
            },
        beforeSend: () =>{
            submitEnding = false

            setTimeout(() => {
                if(!submitEnding) {
                    submitLoading = true;
                    $("#loading-stats-container").show();
                    $("#stats-container").hide();
                }
            }, 200);
        },
        complete: () => {
            submitEnding = true
            if(submitLoading) {
                $("#loading-stats-container").hide();
                if (!onErrorTrigger) {
                    $("#stats-container").fadeIn(500);
                }
            }
        },
    }).responseText;

}

function getInfos(period, selected){
    const url = formatUrl("/api/stats/", period, selected)
    url.slice(2)
    //Fetch data
    $.ajax({
        url: url,
        dataType:"json",
        async: true,
        error: function(XMLHttpRequest, textStatus, errorThrown) {
            const data = XMLHttpRequest.responseJSON
            if(data && data.success != undefined && !data.success){
                onError(data.error)
            }else {
                onError(`Code ${XMLHttpRequest.status}: ${XMLHttpRequest.statusText}`)
            }
        },
        success: function(data){
            if(data.success != undefined && !data.success){
                onError(data.error)
            }
            updateSubmitInfos(data.submit)
            updateFilesInfos(data.file)
            updateSizeInfos(data.submit_size)
            updateMetrics(data.metrics)
        },
        beforeSend: () =>{
            setTimeout(() => {
                if(!statsEnding) {
                    statsLoading = true;
                    $("#loading-stats-container").show();
                    $("#stats-container").hide();
                }
            }, 200);
        },
        complete: () => {
            statsEnding = true
            if(statsLoading) {
                $("#loading-stats-container").hide();
                if (!onErrorTrigger) {
                    $("#stats-container").fadeIn(500);
                }
            }
        },
    }).responseText;
}

function formatUrl(base, period, selected){
    let url = base
    if(period == "year"){
        url += `/year/${selected}`
    }else if(period == "month"){
        url += `/month/${selected}`
    }else if (period == "week"){
        url += `/week/${selected}`
    }else if (period == "day"){
        url += `/day/${selected}`
    }
    return url
}
