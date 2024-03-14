import React, { useEffect, useReducer, useState } from "react"
import { portalApiCall } from "shared/api"
import { reduceByMerge, dhcpFixedHostModalInitialState, deviceManagerInitialState } from "react_components/shared/reducer";

import AddIcon from '@mui/icons-material/Add';
import SettingsInputComponentIcon from '@mui/icons-material/SettingsInputComponent';
import Button from "@mui/material/Button";
import CircularProgress from "@mui/material/CircularProgress";
import Grid from "@mui/material/Grid";
import Tooltip  from "@mui/material/Tooltip";
import {
  DataGrid, GridActionsCellItem
} from "@mui/x-data-grid";

import ThemeProvider from "react_components/shared/ThemeProvider"

import useMatchMedia from "./useMatchMedia"
import NewDeviceModal from "./NewDeviceModal"
import BinatSwitch from "./BinatSwitch"
import DeleteDeviceButton from "./DeleteDeviceButton"
import PortForwardsManager from "./PortForwardsManager"
import StaticIpSelect from "./StaticIpSelect"
import DhcpFixedHostModal from "./DhcpFixedHostModal"
import DhcpFixedHostButton from "./DhcpFixedHostButton"

const fetchAll = async ({ setState }) => {
  await portalApiCall({
    collection: "devices",
    success: ({ data }) => { setState({ devices: data }) },
  })
  await portalApiCall({
    collection: "static_ips",
    success: ({ data }) => { setState({ static_ips: data }) },
  })
  await portalApiCall({
    collection: "account",
    success: ({ data }) => { setState({ account: data }) },
  })
}

const initScheduler = async ({ state, setState }) => {
  if (!state.showNewDeviceModal) {
    await fetchAll({ setState })
    setState({ loading: false })
  }

  setTimeout(() => { initScheduler({ state, setState }) }, 10000)
}

const buildColumns = ({ state, setState, isDeviceResolution, setDhcpFixedHostModalState }) => [
  {
    field: "Icon",
    flex: .1,
    headerName: "",
    sortable: false,
    filterable: false,
    renderCell: params => (
      <Tooltip title={params.row.vendor || ""} placement="top" arrow>
        <i className={params.row.fa_icon + " mx-auto"}></i>
      </Tooltip>
    ),
  },
  {
    field: "name",
    headerName: __("Name"),
    flex: 1,
    editable: true,
  },
  { field: "mac", headerName: __("MAC"), flex: 1 },
  {
    field: "ip",
    headerName: __("IP"),
    flex: 1,
    renderCell: params => (
      <span>
        {params.row.ip || __("Unknown")}
        {params.row.public_ip ? ` / ${params.row.public_ip}` : ""}
      </span>
    ),
  },
  isDeviceResolution ? {
    field: "manufacturer",
    flex: .5,
    headerName: __("Manufacturer"),
    renderCell: params => (
      <span>
        {params.row.vendor || __("Unknown")}
      </span >
    ),
  } : null,
  state.account["is_virtual_gateway?"] ? {
    field: "binat",
    headerName: __("BiNAT"),
    flex: .4,
    renderCell: params => (
      <BinatSwitch record={params.row} {...{ setState, fetchAll }} />
    ),
  } : null,
  state.account["has_static_vta?"] ? {
    field: "dhcp_fixed_host",
    headerName: __("DHCP Reservation"),
    flex: .4,
    renderCell: params => (
      <DhcpFixedHostButton {...{params, setDhcpFixedHostModalState}} />
    )
  } : null,
  state.static_ips.length ? {
    field: "static_ip",
    headerName: __("Static IP"),
    flex: .8,
    renderCell: params => (
      <StaticIpSelect record={params.row} {...{ state, setState, fetchAll }} />
    ),
  } : null,
  {
    field: "Actions",
    type: "actions",
    flex: .5,
    align: "right",
    getActions: params => [
      state.account["is_virtual_gateway?"] && !params.row.binat ? (
        <GridActionsCellItem
          icon={(
            <Tooltip title={__("Port Forwards")} placement="top" arrow>
              <SettingsInputComponentIcon />
            </Tooltip>
          )}
          label="Port Forwards"
          onClick={() => { setState({ managePortForwardsFor: params.row.id }) }}
          color="info"
        />
      ) : null,
      state.account.lock_devices ? null : (
        <DeleteDeviceButton id={params.row.id} {...{ setState, fetchAll }} />
      ),
    ].filter(Boolean),
  },
].filter(Boolean)

const processInlineEdit = async ({ field, id, value }) => {
  if (field == "name") {
    await portalApiCall({
      method: "PATCH",
      collection: "devices",
      record_id: id,
      body: { name: value },
    })
  }
}

const DeviceManager = (props) => {
  const [state, setState] = useReducer(reduceByMerge, deviceManagerInitialState)
  const [dhcpFixedHostModalState, setDhcpFixedHostModalState] = useReducer(reduceByMerge, dhcpFixedHostModalInitialState)
  const [columnVisibilityModel, setColumnVisibilityModel] = useState({})
  const isDeviceResolution = useMatchMedia("(min-width:992px)", true)
  const columns = buildColumns({ state, setState, isDeviceResolution, setDhcpFixedHostModalState })
  const handleClick = () => { setState({ showNewDeviceModal: true }) }


  useEffect(() => { initScheduler({ state, setState }) }, [])

  const {darkMode} = props
  const theme = darkMode ? "dark" : "light"

  return (
    <ThemeProvider theme={theme}>
      <div>
        <Grid container justifyContent="space-between">
          <h2>{__("Devices")}</h2>
          <div>
            <Button
              color="primary" startIcon={<AddIcon />} onClick={handleClick}
            >{__("Add")}</Button>
          </div>
        </Grid>
        {
          state.loading ? <CircularProgress /> : (
            <div style={{ width: "100%", overflowX: "auto" }}>
              <DataGrid
                columns={columns}
                rows={state.devices}
                columnVisibilityModel={columnVisibilityModel}
                onColumnVisibilityModelChange={
                  (newModel) => setColumnVisibilityModel(newModel)
                }
                autoHeight
                sx={{ backgroundColor: "background.paper", minWidth: "60em" }}
                hideFooter
                disableSelectionOnClick
                onCellEditCommit={processInlineEdit}
              />
              {
                state.managePortForwardsFor ? (
                  <PortForwardsManager
                    key={state.managePortForwardsFor || ""}
                    deviceId={state.managePortForwardsFor}
                    setParentState={setState}
                  />
                ) : null
              }
            </div>
          )
        }
        <NewDeviceModal {...{ state, setState, fetchAll }} />
        <DhcpFixedHostModal {...{ setState, fetchAll, dhcpFixedHostModalState, setDhcpFixedHostModalState}} /> {/* setState and FetchAll only used to reset local state via API after action is taken by user, possible todo: make a function that does this and pass in that function */}
      </div>
    </ThemeProvider>
  )
}

export default DeviceManager
