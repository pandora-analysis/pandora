
function getDisabledWorkers(){
    return $('#workers-selection input[type="checkbox"]:not(:checked)').map((_, value) => value.name).get()
}
