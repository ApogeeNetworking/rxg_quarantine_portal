import React, {  useState } from "react";
import { portalApiCall } from "shared/api";

import NativeSelect from '@mui/material/NativeSelect';

const changeStaticIp = async ({
  event, record, setWorking, setState, fetchAll
}) => {
  setWorking(true)
  await portalApiCall({
    collection: "devices",
    record_id: record.id,
    method: "PATCH",
    body: { static_ip_id: event.target.value },
    success: ({ data }) => {
      record.static_ip_id = data.static_ip_id
      fetchAll({ setState })
    },
  })

  setWorking(false)
}

const StaticIpSelect = ({ record, state, setState, fetchAll }) => {
  const [working, setWorking] = useState(false)
  const handleChange = () => changeStaticIp({
    event, record, setWorking, setState, fetchAll
  })

  return (
    <NativeSelect
      value={record.static_ip_id || ""}
      style={{ width: "100%" }}
      size="small"
      onChange={handleChange}
    >
      <option key="" value="">-</option>
      {
        state.static_ips.filter(static_ip => (
          !static_ip.devices.length || static_ip.id == record.static_ip_id
        )).map(static_ip => (
          <option key={static_ip.id} value={static_ip.id} >
            {static_ip.public_ip}
          </option>
        ))
      }
    </NativeSelect>
  )
}

export default StaticIpSelect
