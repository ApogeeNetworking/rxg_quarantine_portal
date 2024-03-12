import React, { useEffect, useReducer, useRef, useState } from "react"
import { Modal } from "react_components/shared"
import { portalApiCall } from "shared/api"

import { useSnackbar } from "notistack"

import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import SaveIcon from "@mui/icons-material/Save";
import Button from "@mui/material/Button";
import CircularProgress from "@mui/material/CircularProgress";
import Grid from "@mui/material/Grid";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import {
  DataGrid, GridActionsCellItem, GridToolbarContainer, useGridApiContext
} from "@mui/x-data-grid"

import NewPortForwardModal from "./NewPortForwardModal"
import DeletePortForwardButton from "./DeletePortForwardButton"

const protocolValues = ["tcp udp", "tcp", "udp"]

const fetchAll = async ({ deviceId, setState }) => {
  await portalApiCall({
    collection: `devices/${deviceId}/port_forwards`,
    success: ({ data }) => { setState({ portForwards: data, loading: false }) },
  })
}

const initScheduler = ({ deviceId, stopSignal, setState }) => {
  if (stopSignal.current) { return }

  fetchAll({ deviceId, setState })
  setTimeout(() => {
    initScheduler({ deviceId, stopSignal, setState })
  }, 5000)
}

const buildColumns = ({ deviceId, setState }) => [
  {
    field: "name",
    headerName: __("Name"),
    flex: 1,
    editable: true,
  },
  {
    field: "external_ports",
    headerName: __("External Ports"),
    flex: 1,
    editable: true,
  },
  {
    field: "internal_ports",
    headerName: __("Internal Ports"),
    flex: 1,
    editable: true,
  },
  {
    field: "protocol",
    type: "singleSelect",
    headerName: __("Protocol"),
    flex: 1,
    valueOptions: protocolValues,
    editable: true,
  },
  {
    field: "actions",
    type: "actions",
    headerName: "",
    flex: .7,
    align: "right",
    getActions: params => {
      const apiRef = useGridApiContext()
      const editMode = Object.keys(apiRef.current.state.editRows).includes(
        params.row.id.toString()
      )

      return [
        editMode ? (
          <GridActionsCellItem
            icon={(
              <Tooltip title={__("Save")} placement="top" arrow><SaveIcon /></Tooltip>
            )}
            label="Save"
            color="info"
            onClick={(e) => {
              apiRef.current.stopRowEditMode({ id: params.row.id })
            }}
          />
        ) : (
          <GridActionsCellItem
            icon={(
              <Tooltip title={__("Edit")} placement="top" arrow><EditIcon /></Tooltip>
            )}
            label="Edit"
            color="info"
            onClick={(e) => {
              apiRef.current.startRowEditMode({ id: params.row.id })
            }}
          />
        ),
        <DeletePortForwardButton id={params.row.id} {...{ deviceId, setState, fetchAll }} />,
      ].filter(Boolean)
    },
  },
]

const editToolbar = ({ state, setState }) => {
  return (
    <GridToolbarContainer>
      <Grid container justifyContent="space-between">
        <Typography component="h2" variant="h6">{__("Port Forwards")}</Typography>
        <div>
          <Button
            color="primary"
            startIcon={<AddIcon />}
            disabled={state.loading}
            onClick={() => { setState({ showNewPortForwardModal: true }) }}
          >{__("Add")}</Button>
        </div>
      </Grid>
    </GridToolbarContainer>
  )
}

const processRowUpdate = ({
  deviceId, state, setState, fetchAll, enqueueSnackbar
}) => async(newRecord, oldRecord) => {
  let success = false
  await portalApiCall({
    collection: `devices/${deviceId}/port_forwards`,
    record_id: newRecord.id,
    method: "PATCH",
    body: newRecord,
    success: () => {
      success = true
      enqueueSnackbar("Update successful!", { variant: "success" })
    },
    error: ({ data }) => {
      enqueueSnackbar(
        `Error: ${data ? data.exception : "Invalid record."}`,
        { variant: "error" },
      )
    },
  })

  return success ? newRecord : oldRecord
}

const PortForwardsManager = ({ deviceId, setParentState }) => {
  const [state, setState] = useReducer(
    (state, newState) => ({ ...state, ...newState }),
    { loading: true, portForwards: [], showNewPortForwardModal: false },
  )
  const columns = buildColumns({ deviceId, setState })
  const { enqueueSnackbar, closeSnackbar } = useSnackbar()

  useEffect(() => {
    // We use a stopSignal for this scheduler instance to stop it when the
    // modal is closed.
    const stopSignal = { current: false }
    initScheduler({ deviceId, stopSignal, setState })

    return () => { stopSignal.current = true }
  }, [])

  return (
    <Modal
      size="xl"
      open={true}
      onClose={() => { setParentState({ managePortForwardsFor: null }) }}
    >
      {
        state.loading ? <CircularProgress /> : <DataGrid
          columns={columns}
          rows={state.portForwards}
          autoHeight
          sx={{ minWidth: "40em", border: 0 }}
          density="compact"
          hideFooter
          disableSelectionOnClick
          editMode="row"
          experimentalFeatures={{ newEditingApi: true }}
          components={{ Toolbar: editToolbar }}
          componentsProps={{ toolbar: { state, setState } }}
          processRowUpdate={processRowUpdate({
            deviceId, setState, fetchAll, enqueueSnackbar
          })}
        />
      }
      <NewPortForwardModal {...{
        deviceId, state, setState, fetchAll, protocolValues
      }} />
    </Modal>
  )
}

export default PortForwardsManager
