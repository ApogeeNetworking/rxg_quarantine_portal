import React, { useState } from "react"
import { portalApiCall } from "shared/api"

import Switch from "@mui/material/Switch";

const switchBinat = async ({ record, setWorking, setState, fetchAll }) => {
  setWorking(true)

  await portalApiCall({
    collection: "devices",
    record_id: record.id,
    method: "PATCH",
    body: { binat: !record.binat },
    success: ({ data }) => {
      record.binat = data.binat
      fetchAll({ setState })
    },
  })

  setWorking(false)
}

const BinatSwitch = ({ record, setState, fetchAll }) => {
  const [working, setWorking] = useState(false)
  const handleChange = () => switchBinat({
    record, setWorking, setState, fetchAll
  })

  return (
    <Switch
      checked={record.binat}
      onChange={handleChange}
      disabled={working}
      size="small"
    />
  )
}

export default BinatSwitch
