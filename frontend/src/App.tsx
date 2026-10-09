import { useEffect, useRef, useState, type ReactNode } from 'react'
import { GetDevices, SetBlocked, SetRateLimit, Status } from '../bindings/github.com/saif/spoofer/deviceservice'
import type { DeviceView } from '../bindings/github.com/saif/spoofer/models'

type Page = 'devices' | 'activity' | 'rules' | 'settings'

type Unit = 'kb' | 'mb' | 'gb'

const UNIT_KB: Record<Unit, number> = { kb: 1, mb: 1000, gb: 1000 * 1000 }

function RateControl({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
    return (
        <label className="rate-control">
            <span className="rate-label">{label}</span>
            <input
                className="rate-input"
                type="number"
                min="0"
                placeholder="0"
                value={value}
                onChange={(e) => onChange(e.target.value)}
            />
        </label>
    )
}

function DeviceControls({ device, onError }: { device: DeviceView; onError: (msg: string) => void }) {
    const [up, setUp] = useState('')
    const [down, setDown] = useState('')
    const [upUnit, setUpUnit] = useState<Unit>('kb')
    const [downUnit, setDownUnit] = useState<Unit>('kb')

    // Reflect the engine's own flag so the checkbox can't drift out of sync
    // with what is actually in the FORWARD chain.
    const blocked = (device.state ?? []).includes('blocked')

    // Seed the boxes from the live limit once it first appears, so clicking
    // Apply without touching a direction re-sends its current value instead of
    // reading as 0 and clearing it.
    const seeded = useRef(false)
    useEffect(() => {
        if (seeded.current) return
        const upKB = device.upLimitKB ?? 0
        const downKB = device.downLimitKB ?? 0
        if (upKB > 0) {
            setUp(String(Math.round(upKB)))
            setUpUnit(upKB >= 1000 * 1000 ? 'gb' : upKB >= 1000 ? 'mb' : 'kb')
        }
        if (downKB > 0) {
            setDown(String(Math.round(downKB)))
            setDownUnit(downKB >= 1000 * 1000 ? 'gb' : downKB >= 1000 ? 'mb' : 'kb')
        }
        if (upKB > 0 || downKB > 0) seeded.current = true
    }, [device.upLimitKB, device.downLimitKB])

    const apply = () => {
        // 0 means unlimited; anything higher is sent as typed.
        const upKB = (Number(up) || 0) * UNIT_KB[upUnit]
        const downKB = (Number(down) || 0) * UNIT_KB[downUnit]
        SetRateLimit(device.ip, upKB, downKB).catch((err) => onError(String(err)))
    }

    return (
        <div className="device-controls">
            <div className="rate-pair">
                <RateControl label="Up" value={up} onChange={setUp} />
                <select className="rate-select" value={upUnit} onChange={(e) => setUpUnit(e.target.value as Unit)}>
                    <option value="kb">kb</option>
                    <option value="mb">mb</option>
                    <option value="gb">gb</option>
                </select>
            </div>
            <div className="rate-pair">
                <RateControl label="Down" value={down} onChange={setDown} />
                <select className="rate-select" value={downUnit} onChange={(e) => setDownUnit(e.target.value as Unit)}>
                    <option value="kb">kb</option>
                    <option value="mb">mb</option>
                    <option value="gb">gb</option>
                </select>
            </div>
            <button className="apply-btn" onClick={apply}>Apply</button>
            <label className="block-check">
                <input
                    type="checkbox"
                    checked={blocked}
                    onChange={(e) => {
                        SetBlocked(device.ip, e.target.checked).catch((err) => onError(String(err)))
                    }}
                />
                <span>Block</span>
            </label>
        </div>
    )
}

function DevicesPage() {
    const [devices, setDevices] = useState<DeviceView[]>([])
    const [error, setError] = useState('')
    const [startupError, setStartupError] = useState('')

    useEffect(() => {
        const t = setInterval(() => {
            GetDevices().then((result) => setDevices(result ?? []))
            Status().then((s) => setStartupError(s?.error ?? ''))
        }, 1000)
        return () => clearInterval(t)
    }, [])
    return (
        <div className="page">
            <div className="page-header">
                <h2>Devices</h2>
                <p>{devices.length} devices on the current session</p>
            </div>
            {startupError && <div className="error-bar">{startupError}</div>}
            {error && <div className="error-bar">{error}</div>}
            <div className="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>IP</th>
                            <th>MAC</th>
                            <th>Vendor</th>
                            <th className="rate-head">Up</th>
                            <th className="rate-head">Down</th>
                            <th>State</th>
                            <th>Controls</th>
                        </tr>
                    </thead>
                    <tbody>
                        {devices.map((d) => (
                            <tr key={d.ip}>
                                <td>{d.name}</td>
                                <td>{d.ip}</td>
                                <td>{d.mac}</td>
                                <td>{d.vendor}</td>
                                <td className="rate-cell">
                                    {d.upRate}
                                    {d.upLimit && <span className="limit-note">cap {d.upLimit}</span>}
                                </td>
                                <td className="rate-cell">
                                    {d.downRate}
                                    {d.downLimit && <span className="limit-note">cap {d.downLimit}</span>}
                                </td>
                                <td>
                                    <div className="badges">
                                        {(d.state ?? []).map((s) => (
                                            <span key={s} className={`badge badge-${s}`}>{s}</span>
                                        ))}
                                    </div>
                                </td>
                                <td className="controls-col"><DeviceControls device={d} onError={setError} /></td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}

function PlaceholderPage({ title }: { title: string }) {
    return (
        <div className="page placeholder">
            <h2>{title}</h2>
            <p>This page is ready for the next feature.</p>
        </div>
    )
}

export default function App() {
    const page: Page = 'devices'

    return (
        <div className="app-shell">
            <header className="topbar">
                <div>
                    <strong>fmmon</strong>
                    <span className="muted"> / network monitor</span>
                </div>
                <div className="topbar-right">
                    <span className="pill">iface: enp0s31f6</span>
                    <span className="pill">ipfwd: on</span>
                    <span className="pill">tc: active</span>
                </div>
            </header>
            <div className="app-body">
                <main className="content">
                    {(() => {
                        const pages: Record<Page, ReactNode> = {
                            devices: <DevicesPage />,
                            activity: <PlaceholderPage title="Activity" />,
                            rules: <PlaceholderPage title="Rules" />,
                            settings: <PlaceholderPage title="Settings" />,
                        }
                        return pages[page]
                    })()}
                </main>
            </div>
        </div>
    )
}
