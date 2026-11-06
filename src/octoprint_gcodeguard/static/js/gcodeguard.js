$(function () {
    function GcodeGuardViewModel() {
        var self = this;
        self.onDataUpdaterPluginMessage = function (plugin, data) {
            if (plugin !== "gcodeguard" || !data || !data.text) {
                return;
            }
            new PNotify({
                title: "GcodeGuard",
                text: _.escape(data.text),
                type: data.type === "error" ? "error" : "notice",
                hide: data.type !== "error"
            });
        };
    }

    OCTOPRINT_VIEWMODELS.push({
        construct: GcodeGuardViewModel,
        dependencies: [],
        elements: []
    });
});
