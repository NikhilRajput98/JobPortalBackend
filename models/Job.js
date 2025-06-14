import mongoose from "mongoose";

const jobSchema = new mongoose.Schema({
    company: {
        type: mongoose.Schema.Types.ObjectId, 
        ref: "Company", 
        required: true
    },
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    location: {
        type: String,
        required: true
    },
    salary: {
        type: String
    },
    type: {
        type: String,
        enum: ["Full-Time", "Part-Time", "Internship", "Remote"]
    },
    openings: {
        type: Number,
        default: 1
    },
    deadline: {
        type: Date,
    }
},{timestamps: true})

export default mongoose.model("Job", jobSchema);