import {
  OctagonX,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldX,
  UsersRound,
} from "lucide-react";

const controls = [
  {
    key: "normal",
    label: "Start Normal Traffic",
    icon: Play,
    className: "primary",
    handler: "onStartNormal",
  },
  {
    key: "single-source",
    label: "Start Single-Source Flood",
    icon: ShieldX,
    className: "danger",
    handler: "onStartSingleSource",
  },
  {
    key: "multi-source",
    label: "Start Multi-Source Flood",
    icon: UsersRound,
    className: "warning",
    handler: "onStartMultiSource",
  },
  {
    key: "stop",
    label: "Stop Traffic",
    icon: OctagonX,
    className: "neutral",
    handler: "onStop",
  },
  {
    key: "reset",
    label: "Reset Demo",
    icon: RotateCcw,
    className: "neutral",
    handler: "onReset",
  },
  {
    key: "flows",
    label: "Refresh Flow Table",
    icon: RefreshCw,
    className: "neutral",
    handler: "onRefreshFlows",
  },
];

function ControlPanel(props) {
  return (
    <section className="panel control-panel">
      <div className="panel-heading">
        <h2>Controls</h2>
      </div>
      <div className="control-grid">
        {controls.map((control) => {
          const Icon = control.icon;
          const loading = props.busyAction === control.key;
          return (
            <button
              key={control.key}
              className={`control-button ${control.className}`}
              onClick={props[control.handler]}
              disabled={Boolean(props.busyAction)}
              title={control.label}
              type="button"
            >
              <Icon size={18} />
              <span>{loading ? "Working..." : control.label}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

export default ControlPanel;
